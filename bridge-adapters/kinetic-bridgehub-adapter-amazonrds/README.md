# kinetic-bridgehub-adapter-amazonrds
A Kinetic Bridgehub adapter for Amazon RDS

Structures
**
Fields

* BackupRetentionPeriod, MultiAZ, DBInstanceStatus, VpcSecurityGroups, DBInstanceIdentifier, PreferredBackupWindow, PreferredMaintenanceWindow, AvailabilityZone, LatestRestorableTime, ReadReplicaDBInstanceIdentifiers,
Engine, PendingModifiedValues, LicenseModel, DBParameterGroups, Endpoint, EngineVersion, OptionGroupMemberships, DBSecurityGroups, PubliclyAccessible, DBName, AutoMinorVersionUpgrade, InstanceCreateTime,
AllocatedStorage, MasterUsername, DBInstanceClass, DbiResourceId, MonitoringInterval, DBInstanceArn, StorageType, CACertificateIdentifier, DomainMemberships
Queries

Amazon RDS has a plethora of query parameters that can be passed in to filter your search.
Examples can be found at http://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_DescribeDBInstances.html

Methods:

Count: returns a count of DBInstances for the given user based on credentials.  Takes no structure or qualifications.

Return: qualification is DBInstanceIdentifier={DBInstanceIdentifier} | field is one or more of fields in the Fields List above.  Additionally, the field: FreeStorageSpace is an option.  This field returns the remaining storage space on a DBInstance.  Available space remaining will return in bytes.  Qualifications: {db_instance_identifier}.  


Search: returns list of instances by field (available fields listed above in fields).  Qualifications can narrow search by DBInstanceIdentifier by adding 'DBInstanceIdentifier={db_instance_identifier}'.  
