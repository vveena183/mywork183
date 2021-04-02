This wiki doc describes the list of resources for backup & restore in Control Tower env and the backup design plan for all the tools installed by Cloud Shared Services in Cloud 2.0 with config rules.

Backup & Restore:
Cloud2.0 Backup & restore strategy is determined based on

Resource type
Data availability for failures & Disaster Recovery scenario
Backup Cost consideration
Backup Schedule
Setting recovery time objective and control over Restoring Data
ROLES AND RESPONSIBILITIES

RACI Matrix

The RACI matrix is used to describe what the process/procedure roles are for each participant in a certain section of the process flow chart.

The following RACI matrix is a high-level overview of the expectations for each role in relation to the processes/procedures (tasks).
Task	Account Owners	CSS	TBD – Operational Support
Cloud 2.0 CT Management Resources	CI	RA	-
CT Disaster Recovery	CI	RA	-
Facilitate & monitor the overall CT backup plans	CI	RA	-
Cloud 2.0 third party tools	CI	RA	-
Application Resources	RA	CI	-
Applications Disaster Recovery	RA	CI	-
Legend

R = Responsible: Executes the task
A = Accountable: Accountable for final result
C = Consulted: Consulted about the task to provide additional information (2 way communication)
I = Informed: Needs to be kept up-to-date on activities/tasks (1 way communication)

Note: Only one person can be accountable for a process while more than one can be consulted, informed, or responsible.

Cloud2.0 Resources:
Following are the Cloud2.0 resources and tools responsible by CSS team to setup backup plans:

Terraform
AWX
Zabbix
Netbox
Centralized Logging Bucket S3
Squid Proxies
AWS SSO instance
CSS Backup Plan for Tools:
The above listed resources are backed up based on the resource type and the underlying service used for the setup

1. RDS Backup- TFE, Zabbix, AWS, Netbox
RDS is used as a common AWS service for database in the above listed tools Multi tier setup.
Following is the common Backup Strategy used for the all the tools utilizing RDS Automated Backups and AWS Backup Service.

Automated Backups in RDS are by default enabled in the above tools with a backup windows per day and a maintenance window.
DB snapshots by Automated Backup config creates system snapshots every day on top of a manual snapshot during the initial deployment of database.
The first snapshot of a DB instance contains the data of the full DB instance.
The snapshots taken after the first snapshot are incremental snapshots. This means that only the latest changed data is captured and saved.
As the current deployment is a Multi-AZ configuration, backups occur on the standby to reduce impact on the primary
AWS Backup Service
In addition to the daily backups by RDS Automated backup optio, a backup plan is configured in AWS Backup Service with 4 Hourly Cron.
AWS Backup Service takes manual snapshots in RDS as per the backup rules.
Manual Snapshots are default copied to multi region (check "Restore Process" how we use the other region snapshot in case of DR scenario).
RDS Data Restore:

with Automated Backup System Snapshots and AWS Backup Plan in place, RDS provides quite a few restore options and DR plans:

Point-in-time recovery (PITR): process of restoring a database to the state it was in at a specified date and time. When you initiate a point-in-time recovery, transactional logs are applied to the most appropriate daily backup in order to restore your DB instance to the specific requested time. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PIT.html 
Creating a new DB from snapshots in case of failure: If a disaster occurs, you can create a new DB instance by restoring from a DB snapshot. When you restore the DB instance, you choose the name of the DB snapshot from which you want to restore. Then, you provide a name for the new DB instance that is created. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_RestoreFromSnapshot.html 
DR Scenario: In case of region breakdown for Disaster Recovery solution, copy a selected Snapshot to a different destination region and restore the db using the previous procedure. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CopySnapshot.html 
Read Replica (not our current solution) : Though Read Replicas provide the highest RTO and RPO but comes with a high cost compared to restoring the Snapshots. When you enable Read Replica in a different region, Amazon creates a READ ONLY instance in that Region. Incase of DR solution, you can promote your Read Replica to a standalone source server. https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ReadRepl.html 
2. S3 Logging Bucket:
Cloud 2.0 CT architecture established a centralized logging mechanism to a S3 bucket in Logging account.
a Cross-Region replication (CRR) is setup on the S3 logging bucket between us-west-2 and us-east-1 regions.
https://docs.aws.amazon.com/AmazonS3/latest/dev/replication.html 
3. Squid Proxies:
Squid proxies servers are deployed on AWS EC2 instances with a high available architecture
AWS Backup service is configured to backup Squid Proxies EC2 Snapshots on a schedule.
4. AWS SSO Instance:
All data configured in AWS SSO (i.e., directory configurations, permission sets, application instances, and user assignments to AWS account application), is stored in the region where AWS SSO is configured. Also, AWS Organizations only supports one AWS SSO Region at a time.
Switching to a different region SSO instance, procedure needs to be defined to enable automated sync with Azure AD and deploy necessary SSO configuration through TF pipeline.
Config Rules:
Cloud 2.0 is setup with Config service rules to notify and fix the Backup plans failures.
