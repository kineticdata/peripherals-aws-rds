package com.kineticdata.bridgehub.adapter.amazonrds;

import com.kineticdata.bridgehub.adapter.BridgeAdapter;
import com.kineticdata.bridgehub.adapter.BridgeError;
import com.kineticdata.bridgehub.adapter.BridgeRequest;
import com.kineticdata.bridgehub.adapter.BridgeUtils;
import com.kineticdata.bridgehub.adapter.Count;
import com.kineticdata.bridgehub.adapter.Record;
import com.kineticdata.bridgehub.adapter.RecordList;
import com.kineticdata.commons.v1.config.ConfigurableProperty;
import com.kineticdata.commons.v1.config.ConfigurablePropertyMap;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.XML;
import org.json.simple.JSONValue;
import org.slf4j.LoggerFactory;
import org.json.JSONArray;
import org.json.JSONObject;



public class AmazonRdsAdapter implements BridgeAdapter {

    /*----------------------------------------------------------------------------------------------
     * PROPERTIES
     *--------------------------------------------------------------------------------------------*/

    /** Defines the adapter display name */
    public static final String NAME = "Amazon RDS Bridge";

    /** Defines the logger */
    protected static final org.slf4j.Logger logger = LoggerFactory.getLogger(AmazonRdsAdapter.class);

    /** Adapter version constant. */
    public static String VERSION;
    /** Load the properties version from the version.properties file. */
    static {
        try {
            java.util.Properties properties = new java.util.Properties();
            properties.load(AmazonRdsAdapter.class.getResourceAsStream("/"+AmazonRdsAdapter.class.getName()+".version"));
            VERSION = properties.getProperty("version");
        } catch (IOException e) {
            logger.warn("Unable to load "+AmazonRdsAdapter.class.getName()+" version properties.", e);
            VERSION = "Unknown";
        }
    }

    /** Defines the collection of property names for the adapter */
    public static class Properties {
        public static final String ACCESS_KEY = "Access Key";
        public static final String SECRET_KEY = "Secret Key";
        public static final String REGION = "Region";
    }

    private final ConfigurablePropertyMap properties = new ConfigurablePropertyMap(
        new ConfigurableProperty(Properties.ACCESS_KEY).setIsRequired(true),
        new ConfigurableProperty(Properties.SECRET_KEY).setIsRequired(true).setIsSensitive(true),
        new ConfigurableProperty(Properties.REGION).setIsRequired(true)
    );

    private String accessKey;
    private String secretKey;
    private String region;

    /*---------------------------------------------------------------------------------------------
     * SETUP METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public void initialize() throws BridgeError {
        this.accessKey = properties.getValue(Properties.ACCESS_KEY);
        this.secretKey = properties.getValue(Properties.SECRET_KEY);
        this.region = properties.getValue(Properties.REGION);
    }

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getVersion() {
        return VERSION;
    }

    @Override
    public void setProperties(Map<String,String> parameters) {
        properties.setValues(parameters);
    }

    @Override
    public ConfigurablePropertyMap getProperties() {
        return properties;
    }

    private static final Pattern NESTED_FIELD = Pattern.compile("(.*?)\\[.*\\]");
    private static final String FREE_STORAGE_SPACE = "FreeStorageSpace";
    public static final List<String> VALID_STRUCTURES = Arrays.asList(new String[] {
       "DBInstances"
    });

    /*---------------------------------------------------------------------------------------------
     * IMPLEMENTATION METHODS
     *-------------------------------------------------------------------------------------------*/

    @Override
    public Count count(BridgeRequest request) throws BridgeError {
         if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }

        AmazonRdsQualificationParser parser = new AmazonRdsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());

        // The headers that we want to add to the request
        List<String> headers = new ArrayList<String>();

        // Make the request using the built up url/headers and bridge properties count
        HttpResponse response = request("GET","https://rds." + this.region + ".amazonaws.com?Action=DescribeDBInstances&Version=2014-10-31&" + query,headers,this.region,"rds","",this.accessKey,this.secretKey);
        String output;

        try {
            output = EntityUtils.toString(response.getEntity());
        } catch (IOException e) { throw new BridgeError(e); }

        JSONObject jsonOutput = XML.toJSONObject(output);
        Object object = jsonOutput.getJSONObject("DescribeDBInstancesResponse").getJSONObject("DescribeDBInstancesResult").getJSONObject("DBInstances").get("DBInstance");

        int count = 0;
        if (object instanceof JSONObject) { count = 1; }
        else if (object instanceof JSONArray) { count = ((JSONArray)object).length(); }

        return new Count(count);
    }

    @Override
    public Record retrieve(BridgeRequest request) throws BridgeError {
        List<String> fields = request.getFields();
        if (fields == null) throw new BridgeError("'Fields' cannot be left blank");

        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }

        AmazonRdsQualificationParser parser = new AmazonRdsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());

       // The headers that we want to add to the request
        List<String> headers = new ArrayList<String>();

        Matcher instanceMatcher = Pattern.compile("DBInstanceIdentifier=(.*?)(?:&|\\z)").matcher(query);
        if (!instanceMatcher.find()) throw new BridgeError("The query parameter 'DBInstanceIdentifier' is required and cannot be found.");
        String dbInstanceIdentifier = instanceMatcher.group(1);

        Map<String,Object> recordMap = new HashMap<String,Object>();

        // Retrieve dbObject that matches the passed in DBInstanceIdentifier
        JSONObject dbObject = getDBObject(dbInstanceIdentifier,headers);
        // If the freeStorageSpace field was included, retrieve the freeStorageSpace
        // and add it to the recordMap
        if (fields.contains(FREE_STORAGE_SPACE)) {
            Map<String,Object> freeStorageSpace = getFreeStorageSpace(dbInstanceIdentifier,headers);
            recordMap.put(FREE_STORAGE_SPACE,freeStorageSpace);
            fields.remove(FREE_STORAGE_SPACE);
        }
        // Build the rest of the recordMap from dbObject using the passed fields
        for (String field : fields) {
            if (!dbObject.has(field)){
                Matcher m = NESTED_FIELD.matcher(field);
                if (m.matches()) {
                    recordMap.put(m.group(1),dbObject.get(m.group(1)));
                } else {
                    throw new BridgeError("Invalid Field: '" + field + "' is not a valid field");
                }
            } else{
                recordMap.put(field, dbObject.get(field));
            }
        }

        return new Record(recordMap);
    }

    @Override
    public RecordList search(BridgeRequest request) throws BridgeError {
        List<String> fields = request.getFields();
        if (fields == null) throw new BridgeError("'Fields' cannot be left blank");

        if (!VALID_STRUCTURES.contains(request.getStructure())) {
            throw new BridgeError("Invalid Structure: '" + request.getStructure() + "' is not a valid structure");
        }

        AmazonRdsQualificationParser parser = new AmazonRdsQualificationParser();
        String query = parser.parse(request.getQuery(),request.getParameters());

        // The headers that we want to add to the request
        List<String> headers = new ArrayList<String>();

        // Make the request using the built up url/headers and bridge properties search
        HttpResponse response = request("GET","https://rds." + this.region + ".amazonaws.com?Action=DescribeDBInstances&Version=2014-10-31&"+query,headers,this.region,"rds","",this.accessKey,this.secretKey);
        String output;

        try {
            output = EntityUtils.toString(response.getEntity());
        } catch (IOException e) { throw new BridgeError(e); }

        JSONObject jsonOutput = XML.toJSONObject(output);
        Object object = jsonOutput.getJSONObject("DescribeDBInstancesResponse").getJSONObject("DescribeDBInstancesResult").getJSONObject("DBInstances").get("DBInstance");

        JSONArray outputArray;
        if (object instanceof JSONArray) {
            outputArray = (JSONArray)object;
        } else if(object instanceof JSONObject){
            outputArray = new JSONArray();
            outputArray.put((JSONObject)object);
        } else {
            outputArray = new JSONArray();
        }

        List<Record> records = new ArrayList<Record>();
        for (int i = 0; i < outputArray.length(); i++) {
            JSONObject dbInstance = outputArray.getJSONObject(i);
            Map<String,Object> recordObj = new HashMap<String,Object>();
            for (String field : fields) {
                if (FREE_STORAGE_SPACE.equals(field) || field.matches("FreeStorageSpace\\[.*\\]")) {
                    Map<String,Object> freeStorageSpace = getFreeStorageSpace((String)dbInstance.get("DBInstanceIdentifier"),headers);
                    recordObj.put(FREE_STORAGE_SPACE,freeStorageSpace);
                } else if (!dbInstance.has(field)){
                    Matcher m = NESTED_FIELD.matcher(field);
                    if (m.matches()) {
                        recordObj.put(m.group(1),dbInstance.get(m.group(1)));
                    } else {
                        throw new BridgeError("Invalid Field: '" + field + "' is not a valid field");
                    }
                } else{
                    recordObj.put(field,dbInstance.get(field));
                }
            }
            records.add(new Record(recordObj));
        }
        records = BridgeUtils.getNestedFields(fields, records);
        return new RecordList(fields,records);

    }

    /*----------------------------------------------------------------------------------------------
     * HELPER METHODS
     *--------------------------------------------------------------------------------------------*/

    private static final DateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
    private String getTimeCurrentTime(){
        Date date = new Date();
        String currentTime = DATE_FORMAT.format(date);

        return currentTime;
    }

    private String getTimeCurrentTMinusTime(){
        Date oldDate = new Date(System.currentTimeMillis()-5*60*1000);
        String tMinusFiveMins = DATE_FORMAT.format(oldDate);

        return tMinusFiveMins;
    }

    private Map<String,Object> getFreeStorageSpace(String query, List<String>headers)throws BridgeError{
        String currentTime = getTimeCurrentTime();
        String tMinusFiveMins = getTimeCurrentTMinusTime();
       // Make the request using the built up url/headers and bridge properties retrieve
       HttpResponse response = request("GET","https://monitoring."+this.region+".amazonaws.com/?Action=GetMetricStatistics&Version=2010-08-01&Dimensions.member.1.Name=DBInstanceIdentifier&Dimensions.member.1.Value=" + query + "&Statistics.member.1=Minimum&Unit=Bytes&StartTime=" + tMinusFiveMins +"&EndTime=" + currentTime + "&Period=240&Namespace=AWS/RDS&MetricName=FreeStorageSpace&",headers,this.region,"monitoring","",this.accessKey,this.secretKey);
       String output;

       try {
           output = EntityUtils.toString(response.getEntity());
       } catch (IOException e) { throw new BridgeError(e); }

       JSONObject jsonOutput = XML.toJSONObject(output);
       JSONArray outputArray = (JSONArray)jsonOutput.getJSONObject("GetMetricStatisticsResponse").getJSONObject("GetMetricStatisticsResult").getJSONObject("Datapoints").getJSONArray("member");
        if (outputArray == null) {
            throw new BridgeError("The 'Fields' input requires at lease one entry.");
        } else {
                JSONObject jsonObject = outputArray.getJSONObject(0);
                return (Map<String, Object>)JSONValue.parse(jsonObject.toString());
        }
    }

    private JSONObject getDBObject(String query, List<String>headers)throws BridgeError{
        // Make the request using the built up url/headers and bridge properties retrieve
        HttpResponse response = request("GET","https://rds."+this.region+".amazonaws.com/?Action=DescribeDBInstances&Version=2014-10-31&DBInstanceIdentifier=" + query,headers,this.region,"rds","",this.accessKey,this.secretKey);
        String output;

        try {
            output = EntityUtils.toString(response.getEntity());
        } catch (IOException e) { throw new BridgeError(e); }

        JSONObject jsonOutput = XML.toJSONObject(output);
        JSONObject outputArray = (JSONObject)jsonOutput.getJSONObject("DescribeDBInstancesResponse").getJSONObject("DescribeDBInstancesResult").getJSONObject("DBInstances").getJSONObject("DBInstance");
        return outputArray;
    }

    /**
     * This method builds and sends a request to the Amazon EC2 REST API given the inputted
     * data and return a HttpResponse object after the call has returned. This method mainly helps with
     * creating a proper signature for the request (documentation on the Amazon REST API signing
     * process can be found here - http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html),
     * but it also throws and logs an error if a 401 or 403 is retrieved on the attempted call.
     *
     * @param url
     * @param headers
     * @param region
     * @param accessKey
     * @param secretKey
     * @return
     * @throws BridgeError
     */
    private HttpResponse request(String method, String url, List<String> headers, String region, String service, String payload, String accessKey, String secretKey) throws BridgeError {
        // Build a datetime timestamp of the current time (in UTC). This will be sent as a header
        // to Amazon and the datetime stamp must be within 5 minutes of the time on the
        // recieving server or else the request will be rejected as a 403 Forbidden
        DateFormat df = new SimpleDateFormat("yyyyMMdd'T'HHmmss'Z'");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        String datetime = df.format(new Date());
        String date = datetime.split("T")[0];

        // Create a URI from the request URL so that we can pull the host/path/query from it
        URI uri;
        try {
            uri = new URI(url);
        } catch (URISyntaxException e) {
            throw new BridgeError("There was an error parsing the inputted url '"+url+"' into a java URI.",e);
        }

        /* BUILD CANONCIAL REQUEST (uri, query, headers, signed headers, hashed payload)*/

        // Canonical URI (the part of the URL between the host and the ?. If blank, the uri is just /)
        String canonicalUri = uri.getPath().isEmpty() ? "/" : uri.getPath();

        // Canonical Query (parameter names sorted by asc and param names and values escaped
        // and trimmed)
        String canonicalQuery;
        // Trim the param names and values and load the parameters into a map
        Map<String,String> queryMap = new HashMap<String,String>();
        if (uri.getQuery() != null) {
            for (String parameter : uri.getQuery().split("&")) {
                queryMap.put(parameter.split("=")[0].trim(), parameter.split("=")[1].trim());
            }
        }

        StringBuilder queryBuilder = new StringBuilder();
        for (String key : new TreeSet<String>(queryMap.keySet())) {
            if (!queryBuilder.toString().isEmpty()) queryBuilder.append("&");
            queryBuilder.append(URLEncoder.encode(key)).append("=").append(URLEncoder.encode(queryMap.get(key)));
        }
        canonicalQuery = queryBuilder.toString();

        // Canonical Headers (lowercase and sort headers, add host and date headers if they aren't
        // already included, then create a header string with trimmed name and values and a new line
        // character after each header - including the last one)
        String canonicalHeaders;
        // Lowercase/trim each header and header value and load into a map
        Map<String,String> headerMap = new HashMap<String,String>();
        for (String header : headers) {
            headerMap.put(header.split(":")[0].toLowerCase().trim(), header.split(":")[1].trim());
        }
        // If the date and host headers aren't already in the header map, add them
        if (!headerMap.keySet().contains("host")) headerMap.put("host",uri.getHost());
        if (!headerMap.keySet().contains("x-amz-date")) headerMap.put("x-amz-date",datetime);
        // Sort the headers and append a newline to the end of each of them
        StringBuilder headerBuilder = new StringBuilder();
        for (String key : new TreeSet<String>(headerMap.keySet())) {
            headerBuilder.append(key).append(":").append(headerMap.get(key)).append("\n");
        }
        canonicalHeaders = headerBuilder.toString();

        // Signed Headers (a semicolon separated list of heads that were signed in the previous step)
        String signedHeaders = StringUtils.join(new TreeSet<String>(headerMap.keySet()),";");

        // Hashed Payload (a SHA256 hexdigest with the request payload - because the bridge only
        // does GET requests the payload will always be an empty string)
        String hashedPayload = DigestUtils.sha256Hex(payload);

        // Canonical Request (built out of 6 parts - the request method and the previous 5 steps in order
        // - with a newline in between each step and then a SHA256 hexdigest run on the resulting string)
        StringBuilder requestBuilder = new StringBuilder();
        requestBuilder.append(method).append("\n");
        requestBuilder.append(canonicalUri).append("\n");
        requestBuilder.append(canonicalQuery).append("\n");
        requestBuilder.append(canonicalHeaders).append("\n");
        requestBuilder.append(signedHeaders).append("\n");
        requestBuilder.append(hashedPayload);

        logger.debug(requestBuilder.toString());
        // Run the resulting string through a SHA256 hexdigest
        String canonicalRequest = DigestUtils.sha256Hex(requestBuilder.toString());

        /* BUILD STRING TO SIGN (credential scope, string to sign) */

        // Credential Scope (date, region, service, and terminating string [which is always aws4_request)
        String credentialScope = String.format("%s/%s/%s/aws4_request",date,region,service);

        // String to Sign (encryption method, datetime, credential scope, and canonical request)
        StringBuilder stringToSignBuilder = new StringBuilder();
        stringToSignBuilder.append("AWS4-HMAC-SHA256").append("\n");
        stringToSignBuilder.append(datetime).append("\n");
        stringToSignBuilder.append(credentialScope).append("\n");
        stringToSignBuilder.append(canonicalRequest);
        logger.debug(stringToSignBuilder.toString());
        String stringToSign = stringToSignBuilder.toString();

        /* CREATE THE SIGNATURE (signing key, signature) */

        // Signing Key
        byte[] signingKey;
        try {
            signingKey = getSignatureKey(secretKey,date,region,service);
        } catch (Exception e) {
            throw new BridgeError("There was a problem creating the signing key",e);
        }

        // Signature
        String signature;
        try {
            signature = Hex.encodeHexString(HmacSHA256(signingKey,stringToSign));
        } catch (Exception e) {
            throw new BridgeError("There was a problem creating the signature",e);
        }

        // Authorization Header (encryption method, access key, credential scope, signed headers, signature))
        String authorization = String.format("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",accessKey,credentialScope,signedHeaders,signature);

        /* CREATE THE HTTP REQUEST */
        HttpClient client = HttpClients.createDefault();
        HttpRequestBase request;
        try {
            if (method.toLowerCase().equals("get")) {
                request = new HttpGet(url);
            } else if (method.toLowerCase().equals("post")) {
                request = new HttpPost(url);
                ((HttpPost)request).setEntity(new StringEntity(payload));
            } else {
                throw new BridgeError("Http Method '"+method+"' is not supported");
            }
        } catch (UnsupportedEncodingException e) {
            throw new BridgeError(e);
        }

        request.setHeader("Authorization",authorization);
        for (Map.Entry<String,String> header : headerMap.entrySet()) {

            request.setHeader(header.getKey(),header.getValue());
        }

        HttpResponse response;
        try {
            response = client.execute(request);

            if (response.getStatusLine().getStatusCode() == 401 || response.getStatusLine().getStatusCode() == 403) {
                logger.error(EntityUtils.toString(response.getEntity()));
                throw new BridgeError("User not authorized to access this resource. Check the logs for more details.");
            }
        } catch (IOException e) { throw new BridgeError(e); }

        return response;
    }

    static byte[] HmacSHA256(byte[] key, String data) throws Exception {
        String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF8"));
    }

    static byte[] getSignatureKey(String secretKey, String date, String region, String service) throws Exception  {
         byte[] kSecret = ("AWS4" + secretKey).getBytes("UTF8");
         byte[] kDate    = HmacSHA256(kSecret, date);
         byte[] kRegion  = HmacSHA256(kDate, region);
         byte[] kService = HmacSHA256(kRegion, service);
         byte[] kSigning = HmacSHA256(kService, "aws4_request");
         return kSigning;
    }

}
