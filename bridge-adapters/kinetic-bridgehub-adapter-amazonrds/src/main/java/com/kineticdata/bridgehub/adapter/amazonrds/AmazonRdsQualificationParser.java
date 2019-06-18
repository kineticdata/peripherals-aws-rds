package com.kineticdata.bridgehub.adapter.amazonrds;

import com.kineticdata.bridgehub.adapter.QualificationParser;

public class AmazonRdsQualificationParser extends QualificationParser {
    public String encodeParameter(String name, String value) {
        return value;
    }
}
