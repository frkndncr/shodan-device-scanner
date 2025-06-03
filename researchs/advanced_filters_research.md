#### Regular Expression Patterns / Düzenli İfade Kalıpları
```python
# Advanced regex patterns for Shodan
regex_patterns = {
    # Version number extraction
    'apache_versions': r'Apache\/(\d+\.\d+\.\d+)',
    'nginx_versions': r'nginx\/(\d+\.\d+\.\d+)',
    'ssh_versions': r'SSH-(\d+\.\d+)',
    
    # IP address patterns
    'private_ips': r'(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)',
    'turkish_ip_ranges': r'(85\.105\.|88\.249\.|94\.103\.|213\.14\.)',
    
    # Common credential patterns
    'default_passwords': r'(admin|password|123456|default|guest)',
    'weak_passwords': r'^.{1,7}# Advanced Shodan Filters for Penetration Testing

## Overview / Genel Bakış

Advanced Shodan filters represent the cutting-edge of internet-wide reconnaissance, enabling security professionals to perform highly targeted and sophisticated searches across the global internet infrastructure. These filters go beyond basic port and service discovery, providing deep insights into device configurations, vulnerabilities, cryptographic implementations, and behavioral patterns. This comprehensive guide explores the most powerful Shodan filters available in 2025, their practical applications in penetration testing, and the strategic value they provide in cybersecurity assessments.

Gelişmiş Shodan filtreleri, internet çapında keşfin en son teknolojisini temsil eder ve güvenlik uzmanlarının küresel internet altyapısında son derece hedefli ve sofistike aramalar gerçekleştirmesini sağlar. Bu filtreler temel port ve servis keşfinin ötesine geçerek cihaz yapılandırmaları, güvenlik açıkları, kriptografik uygulamalar ve davranışsal kalıplar hakkında derin içgörüler sağlar. Bu kapsamlı kılavuz, 2025'te mevcut olan en güçlü Shodan filtrelerini, bunların sızma testindeki pratik uygulamalarını ve siber güvenlik değerlendirmelerinde sağladıkları stratejik değeri araştırır.

## Core Advanced Filters / Temel Gelişmiş Filtreler

### 1. Vulnerability Detection Filters / Güvenlik Açığı Tespit Filtreleri

#### CVE-Based Vulnerability Scanning / CVE Tabanlı Güvenlik Açığı Taraması
```python
# Critical vulnerability detection filters
vulnerability_filters = {
    # Log4Shell (Critical - CVSS 10.0)
    'log4shell': 'vuln:CVE-2021-44228',
    
    # Spring4Shell (Critical - CVSS 9.8)
    'spring4shell': 'vuln:CVE-2022-22965',
    
    # ProxyShell Exchange (Critical - CVSS 9.8)
    'proxyshell': 'vuln:CVE-2021-34473',
    
    # BlueKeep RDP (Critical - CVSS 9.8)
    'bluekeep': 'vuln:CVE-2019-0708',
    
    # GHOSTCAT Tomcat (High - CVSS 9.8)
    'ghostcat': 'vuln:CVE-2020-1938',
    
    # 2025 Critical Vulnerabilities
    'panos_2025': 'vuln:CVE-2024-3400',  # PAN-OS Command Injection
    'ivanti_2025': 'vuln:CVE-2024-21887', # Ivanti Connect Secure
    'fortra_2025': 'vuln:CVE-2024-0204'   # Fortra FileCatalyst
}

# Multi-CVE vulnerability search
def search_multiple_vulnerabilities(target_country="TR"):
    critical_cves = [
        'CVE-2024-3400', 'CVE-2024-21887', 'CVE-2024-0204',
        'CVE-2021-44228', 'CVE-2022-22965', 'CVE-2021-34473'
    ]
    
    for cve in critical_cves:
        query = f'vuln:{cve} country:{target_country}'
        print(f"Searching for {cve}: {query}")
```

#### Zero-Day and Emerging Threat Detection / Sıfır Gün ve Yeni Ortaya Çıkan Tehdit Tespiti
```python
# Emerging threat detection patterns
emerging_threats = {
    'exposed_k8s': 'product:"Kubernetes" port:8080,10250 country:TR',
    'docker_apis': 'port:2375,2376 "Docker" country:TR',
    'elasticsearch_open': 'port:9200 "elasticsearch" -authentication country:TR',
    'mongodb_open': 'port:27017 "MongoDB" -authentication country:TR',
    'redis_open': 'port:6379 "Redis" -authentication country:TR',
    'etcd_exposed': 'port:2379,2380 "etcd" country:TR'
}
```

### 2. SSL/TLS and Cryptographic Analysis / SSL/TLS ve Kriptografik Analiz

#### Advanced SSL/TLS Fingerprinting / Gelişmiş SSL/TLS Parmak İzi
```python
# Comprehensive SSL/TLS analysis filters
ssl_analysis_filters = {
    # JA3 Client Fingerprinting
    'ja3_malware': 'ssl.ja3:"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4"',
    
    # JA3S Server Fingerprinting  
    'ja3s_apache': 'ssl.ja3s:"ec74a5c51106f0419184d0dd08fb05bc"',
    'ja3s_nginx': 'ssl.ja3s:"eb1d94daa55b49c8716dba5eda51d354"',
    'ja3s_iis': 'ssl.ja3s:"de7b6b3fa90e64c2b08b48bf9c25913a"',
    
    # JARM Active TLS Fingerprinting
    'jarm_cloudflare': 'ssl.jarm:"27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d2"',
    'jarm_akamai': 'ssl.jarm:"29d29d00029d29d00041d41d00041d58c7c57c57c57c57c57c57c57c57c57c57c5"',
    'jarm_f5': 'ssl.jarm:"2ad2ad0002ad2ad0041d41d00041d24a458a375eef0c6480d3f4ef6c8d3a6a5"',
    
    # Certificate Analysis
    'self_signed': 'ssl.cert.subject.cn:ssl.cert.issuer.cn',
    'expired_certs': 'ssl.cert.expired:true',
    'weak_keys': 'ssl.cert.pubkey.bits:<2048',
    'invalid_hostnames': 'ssl.cert.subject.cn:* -ssl.cert.subject.cn:hostname'
}
```

#### Weak Cryptographic Implementations / Zayıf Kriptografik Uygulamalar
```python
# Detecting cryptographic weaknesses
crypto_weaknesses = {
    # Weak SSL/TLS Versions
    'sslv2_enabled': 'ssl.version:sslv2',
    'sslv3_enabled': 'ssl.version:sslv3', 
    'tls10_only': 'ssl.version:tlsv1 -ssl.version:tlsv1.1 -ssl.version:tlsv1.2 -ssl.version:tlsv1.3',
    
    # Weak Cipher Suites
    'rc4_ciphers': 'ssl.cipher:"RC4"',
    'des_ciphers': 'ssl.cipher:"DES"',
    'export_ciphers': 'ssl.cipher:"EXPORT"',
    'null_ciphers': 'ssl.cipher:"NULL"',
    
    # Certificate Issues
    'md5_signatures': 'ssl.cert.sig_alg:"md5"',
    'sha1_signatures': 'ssl.cert.sig_alg:"sha1"',
    'weak_dh_params': 'ssl.dh.bits:<1024',
    
    # Perfect Forward Secrecy
    'no_pfs': '-ssl.cipher:"ECDHE" -ssl.cipher:"DHE"'
}
```

### 3. Network Protocol and Service Analysis / Ağ Protokolü ve Servis Analizi

#### Industrial Control Systems (ICS/SCADA) / Endüstriyel Kontrol Sistemleri
```python
# ICS/SCADA specific filters
ics_scada_filters = {
    # Modbus Protocol (Port 502)
    'modbus_devices': 'port:502 country:TR',
    'modbus_schneider': 'port:502 "schneider" country:TR',
    'modbus_siemens': 'port:502 "siemens" country:TR',
    
    # DNP3 Protocol (Port 20000)
    'dnp3_devices': 'port:20000 country:TR',
    
    # IEC 61850 (Port 102)
    'iec61850_devices': 'port:102 country:TR',
    
    # BACnet (Port 47808)
    'bacnet_devices': 'port:47808 country:TR',
    
    # SCADA HMI Interfaces
    'wonderware_hmi': 'port:80 "wonderware" country:TR',
    'ge_cimplicity': 'port:80 "cimplicity" country:TR',
    'rockwell_factorytalk': 'port:80 "factorytalk" country:TR',
    
    # PLC Programming Interfaces
    'siemens_s7': 'port:102 "siemens" country:TR',
    'allen_bradley': 'port:44818 "allen bradley" country:TR',
    'schneider_unity': 'port:502 "unity" country:TR'
}
```

#### Database and Data Store Detection / Veritabanı ve Veri Deposu Tespiti
```python
# Advanced database discovery
database_filters = {
    # Traditional Databases
    'mysql_exposed': 'port:3306 "mysql" -authentication country:TR',
    'postgresql_open': 'port:5432 "postgresql" -authentication country:TR',
    'mssql_exposed': 'port:1433 "microsoft sql server" country:TR',
    'oracle_exposed': 'port:1521 "oracle" country:TR',
    
    # NoSQL Databases
    'mongodb_open': 'port:27017 "mongodb server information" -authentication country:TR',
    'elasticsearch_open': 'port:9200 "elasticsearch" -authentication country:TR',
    'redis_open': 'port:6379 "redis" -authentication country:TR',
    'cassandra_open': 'port:9042 "cassandra" -authentication country:TR',
    'couchdb_open': 'port:5984 "couchdb" -authentication country:TR',
    
    # Big Data Platforms
    'hadoop_namenode': 'port:9000,50070 "hadoop" country:TR',
    'spark_master': 'port:7077,8080 "spark" country:TR',
    'kafka_brokers': 'port:9092 "kafka" country:TR',
    
    # In-Memory Databases
    'memcached_open': 'port:11211 "memcached" country:TR',
    'hazelcast_open': 'port:5701 "hazelcast" country:TR'
}
```

### 4. Cloud and Container Technology Filters / Bulut ve Konteyner Teknoloji Filtreleri

#### Container Orchestration Platforms / Konteyner Orkestrasyon Platformları
```python
# Container and orchestration discovery
container_filters = {
    # Kubernetes
    'k8s_api_server': 'port:6443,8080 "kubernetes" country:TR',
    'k8s_dashboard': 'port:8080 "kubernetes dashboard" country:TR',
    'k8s_etcd': 'port:2379,2380 "etcd" country:TR',
    'k8s_kubelet': 'port:10250,10255 "kubelet" country:TR',
    
    # Docker
    'docker_api': 'port:2375,2376 "docker" country:TR',
    'docker_registry': 'port:5000 "docker-distribution" country:TR',
    'docker_swarm': 'port:2377 "docker swarm" country:TR',
    
    # Container Registries
    'docker_hub_mirror': 'port:5000 "registry" country:TR',
    'harbor_registry': 'port:80,443 "harbor" country:TR',
    'quay_registry': 'port:80,443 "quay" country:TR',
    
    # Service Mesh
    'istio_pilot': 'port:15010 "istio" country:TR',
    'consul_connect': 'port:8500 "consul" country:TR',
    'linkerd_proxy': 'port:4191 "linkerd" country:TR'
}
```

#### Cloud Service Detection / Bulut Servisi Tespiti
```python
# Cloud infrastructure identification
cloud_filters = {
    # AWS Services
    'aws_metadata': 'http.html:"169.254.169.254"',
    'aws_s3_buckets': 'hostname:"s3.amazonaws.com" OR hostname:"s3-"',
    'aws_elb': 'hostname:"elb.amazonaws.com"',
    'aws_cloudfront': 'ssl.cert.issuer.cn:"Amazon"',
    
    # Azure Services  
    'azure_metadata': 'http.html:"169.254.169.254/metadata"',
    'azure_storage': 'hostname:".blob.core.windows.net"',
    'azure_websites': 'hostname:".azurewebsites.net"',
    
    # Google Cloud
    'gcp_metadata': 'http.html:"metadata.google.internal"',
    'gcp_storage': 'hostname:".storage.googleapis.com"',
    'gcp_app_engine': 'hostname:".appspot.com"',
    
    # Turkish Cloud Providers
    'turkcell_bulut': 'hostname:".bulut.com.tr" country:TR',
    'vargonen_cloud': 'hostname:".vargonen.com" country:TR',
    'bbt_bulut': 'hostname:".bbt.gov.tr" country:TR'
}
```

## Advanced Search Techniques / Gelişmiş Arama Teknikleri

### 1. Boolean Logic and Complex Queries / Boolean Mantık ve Karmaşık Sorgular

#### Multi-Condition Filtering / Çoklu Koşul Filtreleme
```python
# Complex boolean search examples
complex_queries = {
    # Vulnerable web servers in Turkey
    'vulnerable_web_turkey': 
        '(apache OR nginx OR iis) AND country:TR AND (vuln:CVE-2021-44228 OR vuln:CVE-2022-22965)',
    
    # Exposed databases with weak authentication
    'weak_auth_databases':
        '(port:3306 OR port:5432 OR port:27017) AND -authentication AND country:TR',
    
    # IoT devices with default credentials
    'default_cred_iot':
        'device:router AND (http.title:"admin" OR http.title:"login") AND country:TR',
    
    # Industrial systems without encryption
    'unencrypted_ics':
        '(port:502 OR port:102 OR port:20000) AND -ssl AND country:TR',
    
    # Cloud instances with exposed services
    'exposed_cloud_services':
        '(hostname:".amazonaws.com" OR hostname:".azure.com" OR hostname:".googlecloud.com") '
        'AND (port:22 OR port:3389 OR port:5432)'
}
```

#### Regular Expression Patterns / Düzenli İfade Kalıpları
```python
# Advanced regex patterns for Shodan
regex_patterns = {
    # Version number extraction
    'apache_versions': r,  # Passwords shorter than 8 characters
    
    # Configuration file exposure
    'config_files': r'\.(conf|config|cfg|ini|yaml|yml|json)# Advanced Shodan Filters for Penetration Testing

## Overview / Genel Bakış

Advanced Shodan filters represent the cutting-edge of internet-wide reconnaissance, enabling security professionals to perform highly targeted and sophisticated searches across the global internet infrastructure. These filters go beyond basic port and service discovery, providing deep insights into device configurations, vulnerabilities, cryptographic implementations, and behavioral patterns. This comprehensive guide explores the most powerful Shodan filters available in 2025, their practical applications in penetration testing, and the strategic value they provide in cybersecurity assessments.

Gelişmiş Shodan filtreleri, internet çapında keşfin en son teknolojisini temsil eder ve güvenlik uzmanlarının küresel internet altyapısında son derece hedefli ve sofistike aramalar gerçekleştirmesini sağlar. Bu filtreler temel port ve servis keşfinin ötesine geçerek cihaz yapılandırmaları, güvenlik açıkları, kriptografik uygulamalar ve davranışsal kalıplar hakkında derin içgörüler sağlar. Bu kapsamlı kılavuz, 2025'te mevcut olan en güçlü Shodan filtrelerini, bunların sızma testindeki pratik uygulamalarını ve siber güvenlik değerlendirmelerinde sağladıkları stratejik değeri araştırır.

## Core Advanced Filters / Temel Gelişmiş Filtreler

### 1. Vulnerability Detection Filters / Güvenlik Açığı Tespit Filtreleri

#### CVE-Based Vulnerability Scanning / CVE Tabanlı Güvenlik Açığı Taraması
```python
# Critical vulnerability detection filters
vulnerability_filters = {
    # Log4Shell (Critical - CVSS 10.0)
    'log4shell': 'vuln:CVE-2021-44228',
    
    # Spring4Shell (Critical - CVSS 9.8)
    'spring4shell': 'vuln:CVE-2022-22965',
    
    # ProxyShell Exchange (Critical - CVSS 9.8)
    'proxyshell': 'vuln:CVE-2021-34473',
    
    # BlueKeep RDP (Critical - CVSS 9.8)
    'bluekeep': 'vuln:CVE-2019-0708',
    
    # GHOSTCAT Tomcat (High - CVSS 9.8)
    'ghostcat': 'vuln:CVE-2020-1938',
    
    # 2025 Critical Vulnerabilities
    'panos_2025': 'vuln:CVE-2024-3400',  # PAN-OS Command Injection
    'ivanti_2025': 'vuln:CVE-2024-21887', # Ivanti Connect Secure
    'fortra_2025': 'vuln:CVE-2024-0204'   # Fortra FileCatalyst
}

# Multi-CVE vulnerability search
def search_multiple_vulnerabilities(target_country="TR"):
    critical_cves = [
        'CVE-2024-3400', 'CVE-2024-21887', 'CVE-2024-0204',
        'CVE-2021-44228', 'CVE-2022-22965', 'CVE-2021-34473'
    ]
    
    for cve in critical_cves:
        query = f'vuln:{cve} country:{target_country}'
        print(f"Searching for {cve}: {query}")
```

#### Zero-Day and Emerging Threat Detection / Sıfır Gün ve Yeni Ortaya Çıkan Tehdit Tespiti
```python
# Emerging threat detection patterns
emerging_threats = {
    'exposed_k8s': 'product:"Kubernetes" port:8080,10250 country:TR',
    'docker_apis': 'port:2375,2376 "Docker" country:TR',
    'elasticsearch_open': 'port:9200 "elasticsearch" -authentication country:TR',
    'mongodb_open': 'port:27017 "MongoDB" -authentication country:TR',
    'redis_open': 'port:6379 "Redis" -authentication country:TR',
    'etcd_exposed': 'port:2379,2380 "etcd" country:TR'
}
```

### 2. SSL/TLS and Cryptographic Analysis / SSL/TLS ve Kriptografik Analiz

#### Advanced SSL/TLS Fingerprinting / Gelişmiş SSL/TLS Parmak İzi
```python
# Comprehensive SSL/TLS analysis filters
ssl_analysis_filters = {
    # JA3 Client Fingerprinting
    'ja3_malware': 'ssl.ja3:"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4"',
    
    # JA3S Server Fingerprinting  
    'ja3s_apache': 'ssl.ja3s:"ec74a5c51106f0419184d0dd08fb05bc"',
    'ja3s_nginx': 'ssl.ja3s:"eb1d94daa55b49c8716dba5eda51d354"',
    'ja3s_iis': 'ssl.ja3s:"de7b6b3fa90e64c2b08b48bf9c25913a"',
    
    # JARM Active TLS Fingerprinting
    'jarm_cloudflare': 'ssl.jarm:"27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d2"',
    'jarm_akamai': 'ssl.jarm:"29d29d00029d29d00041d41d00041d58c7c57c57c57c57c57c57c57c57c57c57c5"',
    'jarm_f5': 'ssl.jarm:"2ad2ad0002ad2ad0041d41d00041d24a458a375eef0c6480d3f4ef6c8d3a6a5"',
    
    # Certificate Analysis
    'self_signed': 'ssl.cert.subject.cn:ssl.cert.issuer.cn',
    'expired_certs': 'ssl.cert.expired:true',
    'weak_keys': 'ssl.cert.pubkey.bits:<2048',
    'invalid_hostnames': 'ssl.cert.subject.cn:* -ssl.cert.subject.cn:hostname'
}
```

#### Weak Cryptographic Implementations / Zayıf Kriptografik Uygulamalar
```python
# Detecting cryptographic weaknesses
crypto_weaknesses = {
    # Weak SSL/TLS Versions
    'sslv2_enabled': 'ssl.version:sslv2',
    'sslv3_enabled': 'ssl.version:sslv3', 
    'tls10_only': 'ssl.version:tlsv1 -ssl.version:tlsv1.1 -ssl.version:tlsv1.2 -ssl.version:tlsv1.3',
    
    # Weak Cipher Suites
    'rc4_ciphers': 'ssl.cipher:"RC4"',
    'des_ciphers': 'ssl.cipher:"DES"',
    'export_ciphers': 'ssl.cipher:"EXPORT"',
    'null_ciphers': 'ssl.cipher:"NULL"',
    
    # Certificate Issues
    'md5_signatures': 'ssl.cert.sig_alg:"md5"',
    'sha1_signatures': 'ssl.cert.sig_alg:"sha1"',
    'weak_dh_params': 'ssl.dh.bits:<1024',
    
    # Perfect Forward Secrecy
    'no_pfs': '-ssl.cipher:"ECDHE" -ssl.cipher:"DHE"'
}
```

### 3. Network Protocol and Service Analysis / Ağ Protokolü ve Servis Analizi

#### Industrial Control Systems (ICS/SCADA) / Endüstriyel Kontrol Sistemleri
```python
# ICS/SCADA specific filters
ics_scada_filters = {
    # Modbus Protocol (Port 502)
    'modbus_devices': 'port:502 country:TR',
    'modbus_schneider': 'port:502 "schneider" country:TR',
    'modbus_siemens': 'port:502 "siemens" country:TR',
    
    # DNP3 Protocol (Port 20000)
    'dnp3_devices': 'port:20000 country:TR',
    
    # IEC 61850 (Port 102)
    'iec61850_devices': 'port:102 country:TR',
    
    # BACnet (Port 47808)
    'bacnet_devices': 'port:47808 country:TR',
    
    # SCADA HMI Interfaces
    'wonderware_hmi': 'port:80 "wonderware" country:TR',
    'ge_cimplicity': 'port:80 "cimplicity" country:TR',
    'rockwell_factorytalk': 'port:80 "factorytalk" country:TR',
    
    # PLC Programming Interfaces
    'siemens_s7': 'port:102 "siemens" country:TR',
    'allen_bradley': 'port:44818 "allen bradley" country:TR',
    'schneider_unity': 'port:502 "unity" country:TR'
}
```

#### Database and Data Store Detection / Veritabanı ve Veri Deposu Tespiti
```python
# Advanced database discovery
database_filters = {
    # Traditional Databases
    'mysql_exposed': 'port:3306 "mysql" -authentication country:TR',
    'postgresql_open': 'port:5432 "postgresql" -authentication country:TR',
    'mssql_exposed': 'port:1433 "microsoft sql server" country:TR',
    'oracle_exposed': 'port:1521 "oracle" country:TR',
    
    # NoSQL Databases
    'mongodb_open': 'port:27017 "mongodb server information" -authentication country:TR',
    'elasticsearch_open': 'port:9200 "elasticsearch" -authentication country:TR',
    'redis_open': 'port:6379 "redis" -authentication country:TR',
    'cassandra_open': 'port:9042 "cassandra" -authentication country:TR',
    'couchdb_open': 'port:5984 "couchdb" -authentication country:TR',
    
    # Big Data Platforms
    'hadoop_namenode': 'port:9000,50070 "hadoop" country:TR',
    'spark_master': 'port:7077,8080 "spark" country:TR',
    'kafka_brokers': 'port:9092 "kafka" country:TR',
    
    # In-Memory Databases
    'memcached_open': 'port:11211 "memcached" country:TR',
    'hazelcast_open': 'port:5701 "hazelcast" country:TR'
}
```

### 4. Cloud and Container Technology Filters / Bulut ve Konteyner Teknoloji Filtreleri

#### Container Orchestration Platforms / Konteyner Orkestrasyon Platformları
```python
# Container and orchestration discovery
container_filters = {
    # Kubernetes
    'k8s_api_server': 'port:6443,8080 "kubernetes" country:TR',
    'k8s_dashboard': 'port:8080 "kubernetes dashboard" country:TR',
    'k8s_etcd': 'port:2379,2380 "etcd" country:TR',
    'k8s_kubelet': 'port:10250,10255 "kubelet" country:TR',
    
    # Docker
    'docker_api': 'port:2375,2376 "docker" country:TR',
    'docker_registry': 'port:5000 "docker-distribution" country:TR',
    'docker_swarm': 'port:2377 "docker swarm" country:TR',
    
    # Container Registries
    'docker_hub_mirror': 'port:5000 "registry" country:TR',
    'harbor_registry': 'port:80,443 "harbor" country:TR',
    'quay_registry': 'port:80,443 "quay" country:TR',
    
    # Service Mesh
    'istio_pilot': 'port:15010 "istio" country:TR',
    'consul_connect': 'port:8500 "consul" country:TR',
    'linkerd_proxy': 'port:4191 "linkerd" country:TR'
}
```

#### Cloud Service Detection / Bulut Servisi Tespiti
```python
# Cloud infrastructure identification
cloud_filters = {
    # AWS Services
    'aws_metadata': 'http.html:"169.254.169.254"',
    'aws_s3_buckets': 'hostname:"s3.amazonaws.com" OR hostname:"s3-"',
    'aws_elb': 'hostname:"elb.amazonaws.com"',
    'aws_cloudfront': 'ssl.cert.issuer.cn:"Amazon"',
    
    # Azure Services  
    'azure_metadata': 'http.html:"169.254.169.254/metadata"',
    'azure_storage': 'hostname:".blob.core.windows.net"',
    'azure_websites': 'hostname:".azurewebsites.net"',
    
    # Google Cloud
    'gcp_metadata': 'http.html:"metadata.google.internal"',
    'gcp_storage': 'hostname:".storage.googleapis.com"',
    'gcp_app_engine': 'hostname:".appspot.com"',
    
    # Turkish Cloud Providers
    'turkcell_bulut': 'hostname:".bulut.com.tr" country:TR',
    'vargonen_cloud': 'hostname:".vargonen.com" country:TR',
    'bbt_bulut': 'hostname:".bbt.gov.tr" country:TR'
}
```

## Advanced Search Techniques / Gelişmiş Arama Teknikleri

### 1. Boolean Logic and Complex Queries / Boolean Mantık ve Karmaşık Sorgular

#### Multi-Condition Filtering / Çoklu Koşul Filtreleme
```python
# Complex boolean search examples
complex_queries = {
    # Vulnerable web servers in Turkey
    'vulnerable_web_turkey': 
        '(apache OR nginx OR iis) AND country:TR AND (vuln:CVE-2021-44228 OR vuln:CVE-2022-22965)',
    
    # Exposed databases with weak authentication
    'weak_auth_databases':
        '(port:3306 OR port:5432 OR port:27017) AND -authentication AND country:TR',
    
    # IoT devices with default credentials
    'default_cred_iot':
        'device:router AND (http.title:"admin" OR http.title:"login") AND country:TR',
    
    # Industrial systems without encryption
    'unencrypted_ics':
        '(port:502 OR port:102 OR port:20000) AND -ssl AND country:TR',
    
    # Cloud instances with exposed services
    'exposed_cloud_services':
        '(hostname:".amazonaws.com" OR hostname:".azure.com" OR hostname:".googlecloud.com") '
        'AND (port:22 OR port:3389 OR port:5432)'
}
```

#### Regular Expression Patterns / Düzenli İfade Kalıpları
```python
# Advanced regex patterns for Shodan
regex_patterns = {
    # Version number extraction
    'apache_versions': r,
    'backup_files': r'\.(bak|backup|old|orig|save)# Advanced Shodan Filters for Penetration Testing

## Overview / Genel Bakış

Advanced Shodan filters represent the cutting-edge of internet-wide reconnaissance, enabling security professionals to perform highly targeted and sophisticated searches across the global internet infrastructure. These filters go beyond basic port and service discovery, providing deep insights into device configurations, vulnerabilities, cryptographic implementations, and behavioral patterns. This comprehensive guide explores the most powerful Shodan filters available in 2025, their practical applications in penetration testing, and the strategic value they provide in cybersecurity assessments.

Gelişmiş Shodan filtreleri, internet çapında keşfin en son teknolojisini temsil eder ve güvenlik uzmanlarının küresel internet altyapısında son derece hedefli ve sofistike aramalar gerçekleştirmesini sağlar. Bu filtreler temel port ve servis keşfinin ötesine geçerek cihaz yapılandırmaları, güvenlik açıkları, kriptografik uygulamalar ve davranışsal kalıplar hakkında derin içgörüler sağlar. Bu kapsamlı kılavuz, 2025'te mevcut olan en güçlü Shodan filtrelerini, bunların sızma testindeki pratik uygulamalarını ve siber güvenlik değerlendirmelerinde sağladıkları stratejik değeri araştırır.

## Core Advanced Filters / Temel Gelişmiş Filtreler

### 1. Vulnerability Detection Filters / Güvenlik Açığı Tespit Filtreleri

#### CVE-Based Vulnerability Scanning / CVE Tabanlı Güvenlik Açığı Taraması
```python
# Critical vulnerability detection filters
vulnerability_filters = {
    # Log4Shell (Critical - CVSS 10.0)
    'log4shell': 'vuln:CVE-2021-44228',
    
    # Spring4Shell (Critical - CVSS 9.8)
    'spring4shell': 'vuln:CVE-2022-22965',
    
    # ProxyShell Exchange (Critical - CVSS 9.8)
    'proxyshell': 'vuln:CVE-2021-34473',
    
    # BlueKeep RDP (Critical - CVSS 9.8)
    'bluekeep': 'vuln:CVE-2019-0708',
    
    # GHOSTCAT Tomcat (High - CVSS 9.8)
    'ghostcat': 'vuln:CVE-2020-1938',
    
    # 2025 Critical Vulnerabilities
    'panos_2025': 'vuln:CVE-2024-3400',  # PAN-OS Command Injection
    'ivanti_2025': 'vuln:CVE-2024-21887', # Ivanti Connect Secure
    'fortra_2025': 'vuln:CVE-2024-0204'   # Fortra FileCatalyst
}

# Multi-CVE vulnerability search
def search_multiple_vulnerabilities(target_country="TR"):
    critical_cves = [
        'CVE-2024-3400', 'CVE-2024-21887', 'CVE-2024-0204',
        'CVE-2021-44228', 'CVE-2022-22965', 'CVE-2021-34473'
    ]
    
    for cve in critical_cves:
        query = f'vuln:{cve} country:{target_country}'
        print(f"Searching for {cve}: {query}")
```

#### Zero-Day and Emerging Threat Detection / Sıfır Gün ve Yeni Ortaya Çıkan Tehdit Tespiti
```python
# Emerging threat detection patterns
emerging_threats = {
    'exposed_k8s': 'product:"Kubernetes" port:8080,10250 country:TR',
    'docker_apis': 'port:2375,2376 "Docker" country:TR',
    'elasticsearch_open': 'port:9200 "elasticsearch" -authentication country:TR',
    'mongodb_open': 'port:27017 "MongoDB" -authentication country:TR',
    'redis_open': 'port:6379 "Redis" -authentication country:TR',
    'etcd_exposed': 'port:2379,2380 "etcd" country:TR'
}
```

### 2. SSL/TLS and Cryptographic Analysis / SSL/TLS ve Kriptografik Analiz

#### Advanced SSL/TLS Fingerprinting / Gelişmiş SSL/TLS Parmak İzi
```python
# Comprehensive SSL/TLS analysis filters
ssl_analysis_filters = {
    # JA3 Client Fingerprinting
    'ja3_malware': 'ssl.ja3:"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4"',
    
    # JA3S Server Fingerprinting  
    'ja3s_apache': 'ssl.ja3s:"ec74a5c51106f0419184d0dd08fb05bc"',
    'ja3s_nginx': 'ssl.ja3s:"eb1d94daa55b49c8716dba5eda51d354"',
    'ja3s_iis': 'ssl.ja3s:"de7b6b3fa90e64c2b08b48bf9c25913a"',
    
    # JARM Active TLS Fingerprinting
    'jarm_cloudflare': 'ssl.jarm:"27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d2"',
    'jarm_akamai': 'ssl.jarm:"29d29d00029d29d00041d41d00041d58c7c57c57c57c57c57c57c57c57c57c57c5"',
    'jarm_f5': 'ssl.jarm:"2ad2ad0002ad2ad0041d41d00041d24a458a375eef0c6480d3f4ef6c8d3a6a5"',
    
    # Certificate Analysis
    'self_signed': 'ssl.cert.subject.cn:ssl.cert.issuer.cn',
    'expired_certs': 'ssl.cert.expired:true',
    'weak_keys': 'ssl.cert.pubkey.bits:<2048',
    'invalid_hostnames': 'ssl.cert.subject.cn:* -ssl.cert.subject.cn:hostname'
}
```

#### Weak Cryptographic Implementations / Zayıf Kriptografik Uygulamalar
```python
# Detecting cryptographic weaknesses
crypto_weaknesses = {
    # Weak SSL/TLS Versions
    'sslv2_enabled': 'ssl.version:sslv2',
    'sslv3_enabled': 'ssl.version:sslv3', 
    'tls10_only': 'ssl.version:tlsv1 -ssl.version:tlsv1.1 -ssl.version:tlsv1.2 -ssl.version:tlsv1.3',
    
    # Weak Cipher Suites
    'rc4_ciphers': 'ssl.cipher:"RC4"',
    'des_ciphers': 'ssl.cipher:"DES"',
    'export_ciphers': 'ssl.cipher:"EXPORT"',
    'null_ciphers': 'ssl.cipher:"NULL"',
    
    # Certificate Issues
    'md5_signatures': 'ssl.cert.sig_alg:"md5"',
    'sha1_signatures': 'ssl.cert.sig_alg:"sha1"',
    'weak_dh_params': 'ssl.dh.bits:<1024',
    
    # Perfect Forward Secrecy
    'no_pfs': '-ssl.cipher:"ECDHE" -ssl.cipher:"DHE"'
}
```

### 3. Network Protocol and Service Analysis / Ağ Protokolü ve Servis Analizi

#### Industrial Control Systems (ICS/SCADA) / Endüstriyel Kontrol Sistemleri
```python
# ICS/SCADA specific filters
ics_scada_filters = {
    # Modbus Protocol (Port 502)
    'modbus_devices': 'port:502 country:TR',
    'modbus_schneider': 'port:502 "schneider" country:TR',
    'modbus_siemens': 'port:502 "siemens" country:TR',
    
    # DNP3 Protocol (Port 20000)
    'dnp3_devices': 'port:20000 country:TR',
    
    # IEC 61850 (Port 102)
    'iec61850_devices': 'port:102 country:TR',
    
    # BACnet (Port 47808)
    'bacnet_devices': 'port:47808 country:TR',
    
    # SCADA HMI Interfaces
    'wonderware_hmi': 'port:80 "wonderware" country:TR',
    'ge_cimplicity': 'port:80 "cimplicity" country:TR',
    'rockwell_factorytalk': 'port:80 "factorytalk" country:TR',
    
    # PLC Programming Interfaces
    'siemens_s7': 'port:102 "siemens" country:TR',
    'allen_bradley': 'port:44818 "allen bradley" country:TR',
    'schneider_unity': 'port:502 "unity" country:TR'
}
```

#### Database and Data Store Detection / Veritabanı ve Veri Deposu Tespiti
```python
# Advanced database discovery
database_filters = {
    # Traditional Databases
    'mysql_exposed': 'port:3306 "mysql" -authentication country:TR',
    'postgresql_open': 'port:5432 "postgresql" -authentication country:TR',
    'mssql_exposed': 'port:1433 "microsoft sql server" country:TR',
    'oracle_exposed': 'port:1521 "oracle" country:TR',
    
    # NoSQL Databases
    'mongodb_open': 'port:27017 "mongodb server information" -authentication country:TR',
    'elasticsearch_open': 'port:9200 "elasticsearch" -authentication country:TR',
    'redis_open': 'port:6379 "redis" -authentication country:TR',
    'cassandra_open': 'port:9042 "cassandra" -authentication country:TR',
    'couchdb_open': 'port:5984 "couchdb" -authentication country:TR',
    
    # Big Data Platforms
    'hadoop_namenode': 'port:9000,50070 "hadoop" country:TR',
    'spark_master': 'port:7077,8080 "spark" country:TR',
    'kafka_brokers': 'port:9092 "kafka" country:TR',
    
    # In-Memory Databases
    'memcached_open': 'port:11211 "memcached" country:TR',
    'hazelcast_open': 'port:5701 "hazelcast" country:TR'
}
```

### 4. Cloud and Container Technology Filters / Bulut ve Konteyner Teknoloji Filtreleri

#### Container Orchestration Platforms / Konteyner Orkestrasyon Platformları
```python
# Container and orchestration discovery
container_filters = {
    # Kubernetes
    'k8s_api_server': 'port:6443,8080 "kubernetes" country:TR',
    'k8s_dashboard': 'port:8080 "kubernetes dashboard" country:TR',
    'k8s_etcd': 'port:2379,2380 "etcd" country:TR',
    'k8s_kubelet': 'port:10250,10255 "kubelet" country:TR',
    
    # Docker
    'docker_api': 'port:2375,2376 "docker" country:TR',
    'docker_registry': 'port:5000 "docker-distribution" country:TR',
    'docker_swarm': 'port:2377 "docker swarm" country:TR',
    
    # Container Registries
    'docker_hub_mirror': 'port:5000 "registry" country:TR',
    'harbor_registry': 'port:80,443 "harbor" country:TR',
    'quay_registry': 'port:80,443 "quay" country:TR',
    
    # Service Mesh
    'istio_pilot': 'port:15010 "istio" country:TR',
    'consul_connect': 'port:8500 "consul" country:TR',
    'linkerd_proxy': 'port:4191 "linkerd" country:TR'
}
```

#### Cloud Service Detection / Bulut Servisi Tespiti
```python
# Cloud infrastructure identification
cloud_filters = {
    # AWS Services
    'aws_metadata': 'http.html:"169.254.169.254"',
    'aws_s3_buckets': 'hostname:"s3.amazonaws.com" OR hostname:"s3-"',
    'aws_elb': 'hostname:"elb.amazonaws.com"',
    'aws_cloudfront': 'ssl.cert.issuer.cn:"Amazon"',
    
    # Azure Services  
    'azure_metadata': 'http.html:"169.254.169.254/metadata"',
    'azure_storage': 'hostname:".blob.core.windows.net"',
    'azure_websites': 'hostname:".azurewebsites.net"',
    
    # Google Cloud
    'gcp_metadata': 'http.html:"metadata.google.internal"',
    'gcp_storage': 'hostname:".storage.googleapis.com"',
    'gcp_app_engine': 'hostname:".appspot.com"',
    
    # Turkish Cloud Providers
    'turkcell_bulut': 'hostname:".bulut.com.tr" country:TR',
    'vargonen_cloud': 'hostname:".vargonen.com" country:TR',
    'bbt_bulut': 'hostname:".bbt.gov.tr" country:TR'
}
```

## Advanced Search Techniques / Gelişmiş Arama Teknikleri

### 1. Boolean Logic and Complex Queries / Boolean Mantık ve Karmaşık Sorgular

#### Multi-Condition Filtering / Çoklu Koşul Filtreleme
```python
# Complex boolean search examples
complex_queries = {
    # Vulnerable web servers in Turkey
    'vulnerable_web_turkey': 
        '(apache OR nginx OR iis) AND country:TR AND (vuln:CVE-2021-44228 OR vuln:CVE-2022-22965)',
    
    # Exposed databases with weak authentication
    'weak_auth_databases':
        '(port:3306 OR port:5432 OR port:27017) AND -authentication AND country:TR',
    
    # IoT devices with default credentials
    'default_cred_iot':
        'device:router AND (http.title:"admin" OR http.title:"login") AND country:TR',
    
    # Industrial systems without encryption
    'unencrypted_ics':
        '(port:502 OR port:102 OR port:20000) AND -ssl AND country:TR',
    
    # Cloud instances with exposed services
    'exposed_cloud_services':
        '(hostname:".amazonaws.com" OR hostname:".azure.com" OR hostname:".googlecloud.com") '
        'AND (port:22 OR port:3389 OR port:5432)'
}
```

#### Regular Expression Patterns / Düzenli İfade Kalıpları
```python
# Advanced regex patterns for Shodan
regex_patterns = {
    # Version number extraction
    'apache_versions': r,
    
    # Common vulnerabilities in banners
    'outdated_software': r'(Apache\/1\.|nginx\/0\.|OpenSSH_[1-6]\.|PHP\/[1-5]\.)',
    'vulnerable_versions': r'(log4j|spring|struts|drupal|wordpress).*([0-9]+\.[0-9]+)'
}

# Using regex in Shodan queries
def build_regex_query(pattern, target_field="http.html"):
    return f'{target_field}:/{pattern}/ country:TR'
```

### 2. Time-based and Historical Analysis / Zaman Tabanlı ve Tarihsel Analiz

#### Temporal Filtering Techniques / Zamansal Filtreleme Teknikleri
```python
# Time-based analysis filters
temporal_filters = {
    # Recent discoveries (last 30 days)
    'recent_vulnerabilities': 'vuln:CVE-2024-3400 after:2024-11-01',
    
    # Historical comparison
    'trend_analysis': {
        'current_month': 'port:22 country:TR after:2024-11-01',
        'previous_month': 'port:22 country:TR after:2024-10-01 before:2024-11-01',
        'last_year': 'port:22 country:TR after:2023-11-01 before:2023-12-01'
    },
    
    # Seasonal patterns
    'holiday_period_exposure': 'port:3389 country:TR after:2024-12-20 before:2025-01-05',
    
    # Long-term trend monitoring
    'quarterly_assessment': [
        'port:80,443 country:TR after:2024-09-01 before:2024-12-01',  # Q4 2024
        'port:80,443 country:TR after:2024-06-01 before:2024-09-01',  # Q3 2024
        'port:80,443 country:TR after:2024-03-01 before:2024-06-01'   # Q2 2024
    ]
}
```

#### Change Detection and Monitoring / Değişiklik Tespiti ve İzleme
```python
# Infrastructure change monitoring
def monitor_infrastructure_changes():
    baseline_queries = {
        'web_servers': 'port:80,443 org:"Target Organization" country:TR',
        'ssh_services': 'port:22 org:"Target Organization" country:TR',
        'database_services': 'port:3306,5432,1433 org:"Target Organization" country:TR',
        'mail_servers': 'port:25,465,587,993,995 org:"Target Organization" country:TR'
    }
    
    monitoring_schedule = {
        'daily': ['critical_vulnerabilities', 'new_exposures'],
        'weekly': ['service_changes', 'certificate_updates'],
        'monthly': ['infrastructure_growth', 'technology_adoption']
    }
    
    return baseline_queries, monitoring_schedule
```

### 3. Geographic and Network-based Filtering / Coğrafi ve Ağ Tabanlı Filtreleme

#### Advanced Geographic Targeting / Gelişmiş Coğrafi Hedefleme
```python
# Detailed geographic filtering
geographic_filters = {
    # Turkish cities and regions
    'istanbul_infrastructure': 'city:"Istanbul" country:TR',
    'ankara_government': 'city:"Ankara" country:TR org:"gov"',
    'izmir_industrial': 'city:"Izmir" country:TR port:502,102',
    'bursa_automotive': 'city:"Bursa" country:TR org:"automotive"',
    
    # ISP and organization targeting
    'turk_telecom': 'org:"Turk Telekom" country:TR',
    'vodafone_turkey': 'org:"Vodafone Turkey" country:TR',
    'turkcell': 'org:"Turkcell" country:TR',
    'superonline': 'org:"Superonline" country:TR',
    
    # Network range analysis
    'government_networks': 'asn:"AS9121" OR asn:"AS47524"',  # Turkish gov ASNs
    'university_networks': 'org:"university" OR org:"üniversitesi" country:TR',
    'banking_networks': 'org:"bank" OR org:"banka" country:TR',
    
    # Cross-border infrastructure
    'turkey_neighbors': 'country:TR,GR,BG,GE,AM,AZ,IR,IQ,SY',
    'regional_comparison': ['country:TR', 'country:GR', 'country:BG']
}
```

#### Autonomous System Number (ASN) Analysis / Otonom Sistem Numarası Analizi
```python
# ASN-based infrastructure mapping
asn_analysis = {
    # Major Turkish ASNs
    'ttnet': 'asn:AS9121',           # Turk Telekom
    'superonline': 'asn:AS34984',    # Superonline
    'vodafone_tr': 'asn:AS15924',    # Vodafone Turkey
    'turkcell': 'asn:AS16135',       # Turkcell
    'digiturk': 'asn:AS47524',       # Digiturk
    
    # Government and critical infrastructure
    'gov_networks': [
        'asn:AS9121',   # Government networks
        'asn:AS47524',  # Critical infrastructure
        'asn:AS34984'   # Educational institutions
    ],
    
    # Commercial and enterprise
    'enterprise_asns': [
        'asn:AS15924',  # Large enterprises
        'asn:AS16135',  # Financial institutions
        'asn:AS9121'    # Commercial hosting
    ]
}
```

## Specialized Filter Categories / Özelleşmiş Filtre Kategorileri

### 1. Malware and Botnet Detection / Kötü Amaçlı Yazılım ve Botnet Tespiti

#### Command and Control (C2) Infrastructure / Komut ve Kontrol Altyapısı
```python
# Advanced malware detection filters
malware_detection = {
    # Known C2 frameworks
    'cobalt_strike': 'product:"Cobalt Strike" OR ssl.jarm:"07d14d16d21d21d07c42d41d00041d24a458a375eef0c6480d3f4ef6c8d3a6a5"',
    'metasploit': 'http.html:"Metasploit" OR http.title:"Metasploit"',
    'empire': 'http.html:"Empire" OR http.title:"PowerShell Empire"',
    'covenant': 'http.html:"Covenant" OR ssl.cert.subject.cn:"Covenant"',
    
    # Cryptocurrency mining
    'crypto_miners': 'http.html:"xmrig" OR http.html:"monero" OR http.html:"mining"',
    'stratum_pools': 'port:3333,4444,8080 "stratum" OR "mining.pool"',
    
    # Ransomware infrastructure
    'ransomware_panels': 'http.title:"Ransomware" OR http.html:"payment" AND "bitcoin"',
    'tor_gateways': 'http.html:".onion" OR http.title:"Tor Gateway"',
    
    # APT group indicators
    'apt_infrastructure': [
        'ssl.cert.subject.cn:"fake-company.com"',  # Common APT technique
        'http.html:"admin panel" AND country:CN,RU,KP,IR',  # Suspicious origins
        'port:443 ssl.cert.issuer.cn:"Fake CA"'  # Fraudulent certificates
    ]
}
```

#### IoT Botnet Detection / IoT Botnet Tespiti
```python
# IoT botnet identification
iot_botnet_filters = {
    # Mirai and variants
    'mirai_infected': 'device:router "busybox" "enable" country:TR',
    'mirai_scanner': 'port:23,2323 "busybox" "sh" country:TR',
    
    # Gafgyt/Qbot variants
    'gafgyt_infected': 'device:camera "Cross Web Server" country:TR',
    
    # Hajime botnet
    'hajime_infected': 'port:5358 "hajime" country:TR',
    
    # VPNFilter
    'vpnfilter_infected': 'device:router "mikrotik" OR "linksys" OR "netgear" vuln:CVE-2018-10561',
    
    # Dark IoT detection
    'dark_iot_devices': 'device:iot -http.title:"login" -http.title:"admin" country:TR'
}
```

### 2. Certificate and PKI Analysis / Sertifika ve PKI Analizi

#### Certificate Authority Analysis / Sertifika Yetkilisi Analizi
```python
# Advanced certificate analysis
certificate_analysis = {
    # Suspicious certificate authorities
    'suspicious_cas': [
        'ssl.cert.issuer.cn:"WoSign"',          # Compromised CA
        'ssl.cert.issuer.cn:"StartCom"',        # Revoked CA
        'ssl.cert.issuer.cn:"CNNIC"',           # Questionable practices
        'ssl.cert.issuer.cn:"Symantec"'         # Deprecated CA
    ],
    
    # Certificate transparency violations
    'ct_violations': 'ssl.cert.serial:"00" OR ssl.cert.serial:"01"',
    
    # Wildcard certificate abuse
    'wildcard_abuse': 'ssl.cert.subject.cn:"*." AND ssl.cert.issuer.cn:"Let\'s Encrypt"',
    
    # Domain validation issues
    'dv_issues': [
        'ssl.cert.subject.cn:hostname AND ssl.cert.issuer.cn:"DV"',
        'ssl.cert.subject.o:"" AND ssl.cert.issuer.cn:"Let\'s Encrypt"'
    ],
    
    # Extended validation certificates
    'ev_certificates': 'ssl.cert.validation:"extended"',
    
    # Self-signed certificate patterns
    'self_signed_suspicious': 'ssl.cert.subject.cn:ssl.cert.issuer.cn AND country:TR'
}
```

#### Certificate Lifecycle Management / Sertifika Yaşam Döngüsü Yönetimi
```python
# Certificate lifecycle monitoring
cert_lifecycle = {
    # Expiring certificates (next 30 days)
    'expiring_soon': f'ssl.cert.expired:false AND ssl.cert.expires:<"{(datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")}"',
    
    # Recently expired certificates
    'recently_expired': f'ssl.cert.expired:true AND ssl.cert.expires:>"{(datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d")}"',
    
    # Short-lived certificates (< 90 days validity)
    'short_lived': 'ssl.cert.expires:<90d',
    
    # Long-lived certificates (> 2 years validity)
    'long_lived': 'ssl.cert.expires:>730d',
    
    # Certificate renewal patterns
    'renewal_tracking': {
        'rapid_renewal': 'ssl.cert.issued:<7d',
        'overdue_renewal': 'ssl.cert.issued:>730d'
    }
}
```

### 3. Cloud Security Assessment / Bulut Güvenlik Değerlendirmesi

#### Multi-Cloud Environment Discovery / Çoklu Bulut Ortamı Keşfi
```python
# Comprehensive cloud infrastructure mapping
cloud_security_assessment = {
    # AWS infrastructure
    'aws_misconfigurations': {
        'open_s3_buckets': 'hostname:"s3.amazonaws.com" http.status:200',
        'exposed_rds': 'hostname:"rds.amazonaws.com" port:3306,5432',
        'ec2_metadata': 'http.html:"169.254.169.254" country:TR',
        'lambda_functions': 'hostname:"lambda.amazonaws.com" http.status:200'
    },
    
    # Azure infrastructure
    'azure_misconfigurations': {
        'blob_storage_open': 'hostname:".blob.core.windows.net" http.status:200',
        'sql_databases': 'hostname:".database.windows.net" port:1433',
        'app_services': 'hostname:".azurewebsites.net" country:TR'
    },
    
    # Google Cloud Platform
    'gcp_misconfigurations': {
        'cloud_storage': 'hostname:".storage.googleapis.com" http.status:200',
        'compute_instances': 'hostname:".compute.googleapis.com"',
        'app_engine': 'hostname:".appspot.com" country:TR'
    },
    
    # Container orchestration
    'container_exposures': {
        'kubernetes_dashboards': 'port:8080,8001 "kubernetes dashboard" country:TR',
        'docker_apis': 'port:2375,2376 "docker" country:TR',
        'container_registries': 'port:5000 "docker-distribution" country:TR'
    }
}
```

#### Cloud-Native Security Patterns / Bulut Yerel Güvenlik Kalıpları
```python
# Cloud-native security assessment
cloud_native_security = {
    # Service mesh security
    'service_mesh': {
        'istio_control_plane': 'port:15010,15011 "istio" country:TR',
        'envoy_proxies': 'port:10000,15000 "envoy" country:TR',
        'consul_connect': 'port:8500,8502 "consul" country:TR'
    },
    
    # API gateway security
    'api_gateways': {
        'kong_gateways': 'port:8000,8001 "kong" country:TR',
        'traefik_proxies': 'port:80,8080 "traefik" country:TR',
        'nginx_ingress': 'port:80,443 "nginx-ingress" country:TR'
    },
    
    # Monitoring and observability
    'monitoring_tools': {
        'prometheus_servers': 'port:9090 "prometheus" country:TR',
        'grafana_dashboards': 'port:3000 "grafana" country:TR',
        'elk_stack': 'port:5601,9200 "elasticsearch" OR "kibana" country:TR'
    }
}
```

## Penetration Testing Integration / Sızma Testi Entegrasyonu

### 1. Automated Reconnaissance Workflows / Otomatik Keşif İş Akışları

#### Multi-Stage Reconnaissance Pipeline / Çok Aşamalı Keşif Boru Hattı
```python
# Comprehensive penetration testing workflow
class ShodanPenetrationTesting:
    def __init__(self, api_key, target_organization):
        self.api = shodan.Shodan(api_key)
        self.target = target_organization
        
    def phase1_initial_discovery(self):
        """Initial target discovery and profiling"""
        discovery_queries = {
            'organization_assets': f'org:"{self.target}" country:TR',
            'domain_infrastructure': f'hostname:"{self.target}.com"',
            'ip_ranges': f'asn:"{self.get_target_asn()}"',
            'certificate_transparency': f'ssl.cert.subject.cn:"{self.target}"'
        }
        return self.execute_queries(discovery_queries)
    
    def phase2_service_enumeration(self, discovered_ips):
        """Detailed service enumeration on discovered assets"""
        service_queries = {
            'web_services': f'net:{discovered_ips} port:80,443,8080,8443',
            'ssh_services': f'net:{discovered_ips} port:22',
            'database_services': f'net:{discovered_ips} port:3306,5432,1433,27017',
            'remote_access': f'net:{discovered_ips} port:3389,5900,23'
        }
        return self.execute_queries(service_queries)
    
    def phase3_vulnerability_assessment(self, services):
        """Vulnerability identification and prioritization"""
        vuln_queries = {
            'critical_cves': f'net:{services} vuln:CVE-2024-*',
            'default_credentials': f'net:{services} "admin" OR "default"',
            'unencrypted_services': f'net:{services} -ssl port:80,21,23',
            'outdated_software': f'net:{services} (apache/1 OR nginx/0 OR openssh_[1-6])'
        }
        return self.execute_queries(vuln_queries)
    
    def phase4_attack_surface_analysis(self, vulnerabilities):
        """Attack surface mapping and risk assessment"""
        attack_surface = {
            'high_risk_services': self.identify_high_risk_services(vulnerabilities),
            'attack_vectors': self.map_attack_vectors(vulnerabilities),
            'privilege_escalation': self.find_escalation_paths(vulnerabilities),
            'lateral_movement': self.identify_pivot_points(vulnerabilities)
        }
        return attack_surface
```

### 2. Threat Intelligence Integration / Tehdit İstihbaratı Entegrasyonu

#### IOC Correlation and Analysis / IOC Korelasyonu ve Analizi
```python
# Threat intelligence correlation
threat_intelligence_queries = {
    # Known malicious IP ranges
    'malicious_infrastructure': [
        'asn:"AS12345" OR asn:"AS67890"',  # Known malicious ASNs
        'country:CN,RU,KP port:22,3389',   # High-risk countries with remote access
        'ssl.cert.issuer.cn:"Fake Certificate Authority"'
    ],
    
    # Threat actor attribution
    'apt_indicators': {
        'apt1': 'ssl.jarm:"07d14d16d21d21d00042d43d000041d6a0458a375eef0c6480d3f4ef6c8d3a6a5"',
        'apt28': 'http.html:"X-PHP-Originating-Script" country:RU',
        'apt29': 'ssl.cert.subject.cn:"*.cozy-bear.com"',
        'lazarus': 'http.html:"fakesun" country:KP'
    },
    
    # Commodity malware families
    'malware_families': {
        'emotet': 'port:443 ssl.cert.subject.cn:"*.emotet.com"',
        'trickbot': 'port:443 http.html:"trickbot"',
        'ryuk': 'http.html:"ryuk" OR http.title:"ryuk"',
        'conti': 'http.html:"conti" OR ssl.cert.subject.cn:"*.conti.com"'
    }
}
```

### 3. Compliance and Risk Assessment / Uyumluluk ve Risk Değerlendirmesi

#### Regulatory Compliance Checking / Düzenleyici Uyumluluk Kontrolü
```python
# Compliance-focused Shodan queries
compliance_assessment = {
    # PCI DSS compliance
    'pci_dss_violations': {
        'unencrypted_payment': 'port:80 "payment" OR "credit card" country:TR',
        'weak_ssl_payment': 'port:443 ssl.version:tlsv1 "payment" country:TR',
        'exposed_card_data': 'http.html:"4[0-9]{15}" OR http.html:"5[1-5][0-9]{14}"'
    },
    
    # GDPR compliance
    'gdpr_violations': {
        'personal_data_exposure': 'http.html:"email" OR "phone" OR "address" country:TR',
        'unencrypted_personal_data': 'port:80 "personal" OR "profile" country:TR',
        'cookie_violations': 'http.html:"cookie" -"consent" country:TR'
    },
    
    # HIPAA compliance (healthcare)
    'hipaa_violations': {
        'medical_data_exposure': 'http.html:"patient" OR "medical record" country:TR',
        'healthcare_systems': 'org:"hospital" OR "clinic" OR "medical" country:TR',
        'phi_exposure': 'http.html:"SSN" OR "medical ID" country:TR'
    },
    
    # SOX compliance (financial)
    'sox_violations': {
        'financial_systems': 'org:"bank" OR "financial" port:80,443 country:TR',
        'accounting_software': 'http.title:"SAP" OR "Oracle Financials" country:TR',
        'trading_systems': 'port:443 "trading" OR "portfolio" country:TR'
    }
}
```

## Advanced Analysis Techniques / Gelişmiş Analiz Teknikleri

### 1. Machine Learning and Pattern Recognition / Makine Öğrenmesi ve Desen Tanıma

#### Behavioral Anomaly Detection / Davranışsal Anomali Tespiti
```python
# ML-enhanced Shodan analysis
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN

class ShodanMLAnalyzer:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        self.anomaly_detector = IsolationForest(contamination=0.1)
        
    def detect_infrastructure_anomalies(self, target_country="TR"):
        """Detect unusual infrastructure patterns"""
        
        # Collect baseline data
        baseline_data = self.collect_baseline_metrics(target_country)
        
        # Feature engineering
        features = self.extract_features(baseline_data)
        
        # Anomaly detection
        anomalies = self.anomaly_detector.fit_predict(features)
        
        return self.identify_anomalous_hosts(baseline_data, anomalies)
    
    def cluster_similar_services(self, search_results):
        """Cluster similar services for pattern analysis"""
        
        # Extract service fingerprints
        fingerprints = self.extract_service_fingerprints(search_results)
        
        # Clustering
        clusters = DBSCAN(eps=0.3, min_samples=5).fit(fingerprints)
        
        return self.analyze_service_clusters(search_results, clusters)
    
    def predict_attack_likelihood(self, host_data):
        """Predict attack likelihood based on historical patterns"""
        
        risk_features = [
            'open_ports_count',
            'vulnerable_services_count',
            'outdated_software_count',
            'default_credentials_present',
            'encryption_strength',
            'patch_level'
        ]
        
        # Feature extraction and prediction logic here
        return self.calculate_risk_score(host_data, risk_features)
```

### 2. Graph-based Network Analysis / Graf Tabanlı Ağ Analizi

#### Infrastructure Relationship Mapping / Altyapı İlişki Haritalama
```python
# Network topology analysis using graph theory
import networkx as nx
import matplotlib.pyplot as plt

class NetworkTopologyAnalyzer:
    def __init__(self):
        self.infrastructure_graph = nx.Graph()
        
    def build_infrastructure_graph(self, shodan_results):
        """Build network topology graph from Shodan data"""
        
        for result in shodan_results:
            ip = result['ip_str']
            org = result.get('org', 'Unknown')
            asn = result.get('asn', 'Unknown')
            location = result.get('location', {})
            
            # Add nodes
            self.infrastructure_graph.add_node(ip, 
                                             org=org, 
                                             asn=asn, 
                                             country=location.get('country_code'),
                                             ports=result.get('ports', []))
            
            # Add edges based on relationships
            self.add_organizational_edges(ip, org)
            self.add_geolocation_edges(ip, location)
            self.add_asn_edges(ip, asn)
    
    def identify_critical_nodes(self):
        """Identify critical infrastructure nodes"""
        
        # Calculate centrality measures
        betweenness = nx.betweenness_centrality(self.infrastructure_graph)
        closeness = nx.closeness_centrality(self.infrastructure_graph)
        eigenvector = nx.eigenvector_centrality(self.infrastructure_graph)
        
        # Identify critical nodes
        critical_nodes = []
        for node in self.infrastructure_graph.nodes():
            if (betweenness[node] > 0.1 or 
                closeness[node] > 0.8 or 
                eigenvector[node] > 0.1):
                critical_nodes.append(node)
        
        return critical_nodes
    
    def find_attack_paths(self, source, target):
        """Find potential attack paths between nodes"""
        
        try:
            paths = list(nx.all_shortest_paths(self.infrastructure_graph, 
                                             source, target))
            return self.analyze_attack_feasibility(paths)
        except nx.NetworkXNoPath:
            return None
```

## Best Practices and Operational Guidelines / En İyi Uygulamalar ve Operasyonel Kılavuzlar

### 1. Ethical and Legal Considerations / Etik ve Yasal Hususlar

#### Responsible Disclosure Framework / Sorumlu Açıklama Çerçevesi
```python
# Responsible disclosure workflow
responsible_disclosure_process = {
    'discovery_phase': {
        'scope_definition': 'Clearly define authorized testing scope',
        'permission_verification': 'Verify explicit testing authorization',
        'legal_compliance': 'Ensure compliance with local laws and regulations',
        'documentation': 'Maintain detailed logs of all activities'
    },
    
    'assessment_phase': {
        'non_intrusive_testing': 'Limit to passive reconnaissance only',
        'data_minimization': 'Collect only necessary information',
        'privacy_protection': 'Protect personally identifiable information',
        'impact_assessment': 'Evaluate potential impact of findings'
    },
    
    'disclosure_phase': {
        'initial_contact': 'Contact organization through appropriate channels',
        'vulnerability_details': 'Provide clear, actionable vulnerability information',
        'remediation_timeline': 'Allow reasonable time for remediation',
        'public_disclosure': 'Follow responsible disclosure timeline'
    },
    
    'follow_up_phase': {
        'remediation_verification': 'Verify fixes have been implemented',
        'ongoing_monitoring': 'Monitor for similar issues',
        'lessons_learned': 'Document lessons learned for future assessments'
    }
}
```

### 2. API Rate Limiting and Optimization / API Oran Sınırlama ve Optimizasyon

#### Efficient Query Strategies / Verimli Sorgu Stratejileri
```python
# Optimized Shodan API usage
class OptimizedShodanClient:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        self.query_cache = {}
        self.rate_limiter = self.setup_rate_limiter()
        
    def optimized_search(self, query, max_results=1000):
        """Optimized search with caching and rate limiting"""
        
        # Check cache first
        if query in self.query_cache:
            return self.query_cache[query]
        
        # Rate limiting
        self.rate_limiter.wait()
        
        # Execute search with pagination
        results = []
        page = 1
        
        while len(results) < max_results:
            try:
                page_results = self.api.search(query, page=page)
                results.extend(page_results['matches'])
                
                if len(page_results['matches']) < 100:  # No more results
                    break
                    
                page += 1
                self.rate_limiter.wait()
                
            except shodan.APIError as e:
                if "rate limit" in str(e).lower():
                    time.sleep(60)  # Wait 1 minute for rate limit reset
                    continue
                else:
                    raise
        
        # Cache results
        self.query_cache[query] = results[:max_results]
        return results[:max_results]
    
    def batch_search(self, queries, delay=1):
        """Execute multiple queries with proper spacing"""
        
        results = {}
        for query in queries:
            results[query] = self.optimized_search(query)
            time.sleep(delay)  # Respectful delay between queries
            
        return results
```

## Conclusion / Sonuç

Advanced Shodan filters represent a paradigm shift in cybersecurity reconnaissance, transforming how security professionals discover, analyze, and assess internet-exposed infrastructure. The sophisticated filtering capabilities explored in this research—from vulnerability detection and cryptographic analysis to threat intelligence correlation and compliance assessment—provide unprecedented visibility into the global attack surface.

Gelişmiş Shodan filtreleri, siber güvenlik keşfinde bir paradigma değişimini temsil eder ve güvenlik uzmanlarının internete açık altyapıyı keşfetme, analiz etme ve değerlendirme şeklini dönüştürür. Bu araştırmada incelenen sofistike filtreleme yetenekleri—güvenlik açığı tespitinden kriptografik analize, tehdit istihbaratı korelasyonundan uyumluluk değerlendirmesine kadar—küresel saldırı yüzeyine benzersiz görünürlük sağlar.

The integration of machine learning, graph-based analysis, and automated workflows with Shodan's comprehensive database creates powerful capabilities for proactive threat hunting, infrastructure monitoring, and risk assessment. However, with this power comes the responsibility to use these tools ethically and within legal boundaries, ensuring that the benefits of enhanced security visibility do not come at the cost of privacy violations or unauthorized access.

Makine öğrenmesi, graf tabanlı analiz ve otomatik iş akışlarının Shodan'ın kapsamlı veritabanıyla entegrasyonu, proaktif tehdit avcılığı, altyapı izleme ve risk değerlendirmesi için güçlü yetenekler yaratır. Ancak bu güçle birlikte, bu araçları etik ve yasal sınırlar içinde kullanma sorumluluğu gelir; gelişmiş güvenlik görünürlüğünün faydalarının gizlilik ihlalleri veya yetkisiz erişim pahasına gelmemesini sağlamak gerekir.

As the threat landscape continues to evolve with emerging technologies like 5G, IoT proliferation, and quantum computing, the role of advanced reconnaissance tools will become increasingly critical. The techniques and methodologies outlined in this research provide a foundation for developing more sophisticated and effective cybersecurity strategies, enabling organizations to stay ahead of evolving threats while maintaining the delicate balance between security and privacy.

5G, IoT yaygınlaşması ve kuantum bilişim gibi yeni teknolojilerle tehdit manzarası gelişmeye devam ettikçe, gelişmiş keşif araçlarının rolü giderek daha kritik hale gelecektir. Bu araştırmada özetlenen teknikler ve metodolojiler, daha sofistike ve etkili siber güvenlik stratejileri geliştirmek için bir temel sağlar ve kuruluşların güvenlik ile gizlilik arasındaki hassas dengeyi korurken gelişen tehditlerin önünde kalmalarını sağlar.

The future of cybersecurity reconnaissance lies not just in the tools themselves, but in the wisdom and responsibility with which they are wielded. Advanced Shodan filters, when used properly, can significantly enhance our collective cybersecurity posture—but only when deployed with the proper ethical considerations and technical expertise that this powerful capability demands.

Siber güvenlik keşfinin geleceği sadece araçların kendisinde değil, bunların kullanıldığı bilgelik ve sorumlulukta yatar. Gelişmiş Shodan filtreleri, doğru kullanıldığında kollektif siber güvenlik duruşumuzu önemli ölçüde geliştirebilir—ancak yalnızca bu güçlü yeteneğin gerektirdiği uygun etik değerlendirmeler ve teknik uzmanlıkla dağıtıldığında.

## Practical Implementation Examples / Pratik Uygulama Örnekleri

### Turkey-Specific Security Assessment / Türkiye'ye Özel Güvenlik Değerlendirmesi

```python
# Comprehensive Turkey cybersecurity assessment
def turkey_security_assessment():
    """
    Comprehensive cybersecurity assessment for Turkish infrastructure
    Türk altyapısı için kapsamlı siber güvenlik değerlendirmesi
    """
    
    assessment_categories = {
        'critical_infrastructure': {
            'energy_sector': 'country:TR (org:"TEDAŞ" OR org:"BOTAŞ" OR org:"TPAO")',
            'telecommunications': 'country:TR (org:"Turk Telekom" OR org:"Vodafone" OR org:"Turkcell")',
            'banking': 'country:TR (org:"bank" OR org:"banka") port:443,80',
            'government': 'country:TR (org:"gov.tr" OR hostname:"*.gov.tr")',
            'transportation': 'country:TR (org:"TCDD" OR org:"THY" OR org:"İGA")'
        },
        
        'vulnerability_assessment': {
            'unpatched_systems': 'country:TR vuln:CVE-2024-*',
            'default_credentials': 'country:TR (http.title:"admin" OR "default login")',
            'exposed_databases': 'country:TR port:3306,5432,27017 -authentication',
            'weak_encryption': 'country:TR port:443 ssl.version:tlsv1',
            'industrial_exposure': 'country:TR port:502,102,20000'
        },
        
        'threat_intelligence': {
            'malware_infrastructure': 'country:TR (http.html:"botnet" OR "malware")',
            'phishing_sites': 'country:TR http.title:"login" ssl.cert.issuer.cn:"Let\'s Encrypt"',
            'suspicious_certificates': 'country:TR ssl.cert.subject.cn:"*.tk" OR "*.ml"',
            'tor_relays': 'country:TR port:9001,9030'
        }
    }
    
    return assessment_categories

# Automated reporting system
def generate_security_report(assessment_results):
    """Generate comprehensive security assessment report"""
    
    report_sections = {
        'executive_summary': generate_executive_summary(assessment_results),
        'critical_findings': identify_critical_vulnerabilities(assessment_results),
        'risk_matrix': create_risk_assessment_matrix(assessment_results),
        'remediation_plan': develop_remediation_recommendations(assessment_results),
        'compliance_status': assess_regulatory_compliance(assessment_results)
    }
    
    return compile_report(report_sections)
```

### Automated Threat Hunting / Otomatik Tehdit Avcılığı

```python
# Advanced threat hunting automation
class ThreatHuntingAutomation:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        self.threat_signatures = self.load_threat_signatures()
        self.ioc_database = self.initialize_ioc_database()
        
    def continuous_threat_monitoring(self):
        """Continuous threat monitoring and alerting system"""
        
        monitoring_queries = {
            'new_c2_infrastructure': self.build_c2_detection_queries(),
            'compromised_websites': self.build_compromise_detection_queries(),
            'malware_distribution': self.build_malware_detection_queries(),
            'data_exfiltration': self.build_exfiltration_detection_queries()
        }
        
        while True:
            for threat_type, queries in monitoring_queries.items():
                new_threats = self.execute_threat_hunt(queries)
                if new_threats:
                    self.alert_security_team(threat_type, new_threats)
                    self.update_ioc_database(new_threats)
            
            time.sleep(3600)  # Check every hour
    
    def hunt_apt_infrastructure(self, apt_group):
        """Hunt for specific APT group infrastructure"""
        
        apt_signatures = self.threat_signatures.get(apt_group, {})
        
        hunt_queries = []
        for signature_type, signatures in apt_signatures.items():
            for signature in signatures:
                hunt_queries.append(f'{signature_type}:"{signature}" country:TR')
        
        findings = []
        for query in hunt_queries:
            results = self.api.search(query)
            findings.extend(self.analyze_apt_indicators(results, apt_group))
        
        return self.correlate_apt_findings(findings)
```

## Advanced Defensive Applications / Gelişmiş Savunma Uygulamaları

### Proactive Defense Strategies / Proaktif Savunma Stratejileri

```python
# Proactive defense using Shodan intelligence
class ProactiveDefense:
    def __init__(self, api_key, organization_assets):
        self.api = shodan.Shodan(api_key)
        self.assets = organization_assets
        self.baseline = self.establish_security_baseline()
        
    def external_attack_surface_monitoring(self):
        """Monitor external attack surface for changes"""
        
        current_surface = self.scan_external_surface()
        changes = self.compare_with_baseline(current_surface)
        
        if changes['new_services']:
            self.alert_new_services(changes['new_services'])
        
        if changes['new_vulnerabilities']:
            self.prioritize_vulnerabilities(changes['new_vulnerabilities'])
        
        if changes['configuration_changes']:
            self.assess_configuration_drift(changes['configuration_changes'])
        
        self.update_baseline(current_surface)
    
    def threat_landscape_analysis(self):
        """Analyze threat landscape for organization-specific risks"""
        
        industry_threats = self.identify_industry_specific_threats()
        geographic_threats = self.analyze_regional_threat_patterns()
        technology_threats = self.assess_technology_stack_risks()
        
        threat_intelligence = {
            'industry_risks': industry_threats,
            'regional_risks': geographic_threats,
            'technology_risks': technology_threats,
            'combined_risk_score': self.calculate_composite_risk()
        }
        
        return self.generate_threat_briefing(threat_intelligence)
    
    def automated_countermeasures(self, threat_indicators):
        """Implement automated defensive countermeasures"""
        
        countermeasures = {
            'firewall_rules': self.generate_firewall_rules(threat_indicators),
            'dns_blocks': self.create_dns_blocklist(threat_indicators),
            'security_signatures': self.develop_detection_signatures(threat_indicators),
            'threat_intelligence_feeds': self.update_ti_feeds(threat_indicators)
        }
        
        return self.deploy_countermeasures(countermeasures)
```

## References and Further Reading / Kaynaklar ve İleri Okuma

### Primary Sources / Birincil Kaynaklar
- [Shodan Developer Documentation](https://developer.shodan.io/)
- [Shodan Search Query Fundamentals](https://help.shodan.io/the-basics/search-query-fundamentals)
- [Shodan Filter Reference Guide](https://beta.shodan.io/search/filters)
- [Shodan Command Line Interface](https://cli.shodan.io/)

### Security Frameworks and Standards / Güvenlik Çerçeveleri ve Standartları
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PTES (Penetration Testing Execution Standard)](http://www.pentest-standard.org/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)

### Vulnerability Databases / Güvenlik Açığı Veritabanları
- [CVE Database](https://cve.mitre.org/)
- [NVD (National Vulnerability Database)](https://nvd.nist.gov/)
- [Exploit Database](https://www.exploit-db.com/)
- [VulnDB](https://vulndb.cyberriskanalytics.com/)

### Threat Intelligence Sources / Tehdit İstihbaratı Kaynakları
- [MISP (Malware Information Sharing Platform)](https://www.misp-project.org/)
- [OpenIOC](https://www.fireeye.com/services/freeware/openioc.html)
- [STIX/TAXII](https://oasis-open.github.io/cti-documentation/)
- [AlienVault OTX](https://otx.alienvault.com/)

### Turkish Cybersecurity Resources / Türk Siber Güvenlik Kaynakları
- [USOM (Ulusal Siber Olaylara Müdahale Merkezi)](https://www.usom.gov.tr/)
- [BTK (Bilgi Teknolojileri ve İletişim Kurumu)](https://www.btk.gov.tr/)
- [KVKK (Kişisel Verilerin Korunması Kurumu)](https://www.kvkk.gov.tr/)
- [TSE Siber Güvenlik Standartları](https://www.tse.org.tr/)

### Academic Research / Akademik Araştırma
- IEEE Transactions on Network and Service Management
- ACM Computing Surveys - Cybersecurity
- Journal of Cybersecurity and Privacy
- Computers & Security (Elsevier)

### Tools and Utilities / Araçlar ve Yardımcı Programlar
- [Masscan](https://github.com/robertdavidgraham/masscan) - Internet-scale port scanner
- [Nmap](https://nmap.org/) - Network discovery and security auditing
- [Metasploit](https://www.metasploit.com/) - Penetration testing framework
- [Burp Suite](https://portswigger.net/burp) - Web application security testing

**Commit Date**: May 29, 2025  
**Author**: Furkan Dinçer  
**Student ID**: 2420191021  
**Course**: İstinye University - Penetration Testing  
**Specialization**: Advanced Reconnaissance and Threat Intelligence

**Disclaimer / Sorumluluk Reddi**: This research is intended for educational and authorized security testing purposes only. Users must ensure compliance with applicable laws and obtain proper authorization before conducting any security assessments. The author and İstinye University are not responsible for any misuse of the information provided in this document.

Bu araştırma yalnızca eğitim ve yetkili güvenlik testi amaçları için tasarlanmıştır. Kullanıcılar herhangi bir güvenlik değerlendirmesi yapmadan önce geçerli yasalara uygunluğu sağlamalı ve uygun yetkileri almalıdır. Yazar ve İstinye Üniversitesi, bu belgede sağlanan bilgilerin kötüye kullanımından sorumlu değildir.# Advanced Shodan Filters for Penetration Testing

## Overview / Genel Bakış

Advanced Shodan filters represent the cutting-edge of internet-wide reconnaissance, enabling security professionals to perform highly targeted and sophisticated searches across the global internet infrastructure. These filters go beyond basic port and service discovery, providing deep insights into device configurations, vulnerabilities, cryptographic implementations, and behavioral patterns. This comprehensive guide explores the most powerful Shodan filters available in 2025, their practical applications in penetration testing, and the strategic value they provide in cybersecurity assessments.

Gelişmiş Shodan filtreleri, internet çapında keşfin en son teknolojisini temsil eder ve güvenlik uzmanlarının küresel internet altyapısında son derece hedefli ve sofistike aramalar gerçekleştirmesini sağlar. Bu filtreler temel port ve servis keşfinin ötesine geçerek cihaz yapılandırmaları, güvenlik açıkları, kriptografik uygulamalar ve davranışsal kalıplar hakkında derin içgörüler sağlar. Bu kapsamlı kılavuz, 2025'te mevcut olan en güçlü Shodan filtrelerini, bunların sızma testindeki pratik uygulamalarını ve siber güvenlik değerlendirmelerinde sağladıkları stratejik değeri araştırır.

## Core Advanced Filters / Temel Gelişmiş Filtreler

### 1. Vulnerability Detection Filters / Güvenlik Açığı Tespit Filtreleri

#### CVE-Based Vulnerability Scanning / CVE Tabanlı Güvenlik Açığı Taraması
```python
# Critical vulnerability detection filters
vulnerability_filters = {
    # Log4Shell (Critical - CVSS 10.0)
    'log4shell': 'vuln:CVE-2021-44228',
    
    # Spring4Shell (Critical - CVSS 9.8)
    'spring4shell': 'vuln:CVE-2022-22965',
    
    # ProxyShell Exchange (Critical - CVSS 9.8)
    'proxyshell': 'vuln:CVE-2021-34473',
    
    # BlueKeep RDP (Critical - CVSS 9.8)
    'bluekeep': 'vuln:CVE-2019-0708',
    
    # GHOSTCAT Tomcat (High - CVSS 9.8)
    'ghostcat': 'vuln:CVE-2020-1938',
    
    # 2025 Critical Vulnerabilities
    'panos_2025': 'vuln:CVE-2024-3400',  # PAN-OS Command Injection
    'ivanti_2025': 'vuln:CVE-2024-21887', # Ivanti Connect Secure
    'fortra_2025': 'vuln:CVE-2024-0204'   # Fortra FileCatalyst
}

# Multi-CVE vulnerability search
def search_multiple_vulnerabilities(target_country="TR"):
    critical_cves = [
        'CVE-2024-3400', 'CVE-2024-21887', 'CVE-2024-0204',
        'CVE-2021-44228', 'CVE-2022-22965', 'CVE-2021-34473'
    ]
    
    for cve in critical_cves:
        query = f'vuln:{cve} country:{target_country}'
        print(f"Searching for {cve}: {query}")
```

#### Zero-Day and Emerging Threat Detection / Sıfır Gün ve Yeni Ortaya Çıkan Tehdit Tespiti
```python
# Emerging threat detection patterns
emerging_threats = {
    'exposed_k8s': 'product:"Kubernetes" port:8080,10250 country:TR',
    'docker_apis': 'port:2375,2376 "Docker" country:TR',
    'elasticsearch_open': 'port:9200 "elasticsearch" -authentication country:TR',
    'mongodb_open': 'port:27017 "MongoDB" -authentication country:TR',
    'redis_open': 'port:6379 "Redis" -authentication country:TR',
    'etcd_exposed': 'port:2379,2380 "etcd" country:TR'
}
```

### 2. SSL/TLS and Cryptographic Analysis / SSL/TLS ve Kriptografik Analiz

#### Advanced SSL/TLS Fingerprinting / Gelişmiş SSL/TLS Parmak İzi
```python
# Comprehensive SSL/TLS analysis filters
ssl_analysis_filters = {
    # JA3 Client Fingerprinting
    'ja3_malware': 'ssl.ja3:"769,47-53-5-10-49161-49162-49171-49172-50-56-19-4"',
    
    # JA3S Server Fingerprinting  
    'ja3s_apache': 'ssl.ja3s:"ec74a5c51106f0419184d0dd08fb05bc"',
    'ja3s_nginx': 'ssl.ja3s:"eb1d94daa55b49c8716dba5eda51d354"',
    'ja3s_iis': 'ssl.ja3s:"de7b6b3fa90e64c2b08b48bf9c25913a"',
    
    # JARM Active TLS Fingerprinting
    'jarm_cloudflare': 'ssl.jarm:"27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b93f92252d2"',
    'jarm_akamai': 'ssl.jarm:"29d29d00029d29d00041d41d00041d58c7c57c57c57c57c57c57c57c57c57c57c5"',
    'jarm_f5': 'ssl.jarm:"2ad2ad0002ad2ad0041d41d00041d24a458a375eef0c6480d3f4ef6c8d3a6a5"',
    
    # Certificate Analysis
    'self_signed': 'ssl.cert.subject.cn:ssl.cert.issuer.cn',
    'expired_certs': 'ssl.cert.expired:true',
    'weak_keys': 'ssl.cert.pubkey.bits:<2048',
    'invalid_hostnames': 'ssl.cert.subject.cn:* -ssl.cert.subject.cn:hostname'
}
```

#### Weak Cryptographic Implementations / Zayıf Kriptografik Uygulamalar
```python
# Detecting cryptographic weaknesses
crypto_weaknesses = {
    # Weak SSL/TLS Versions
    'sslv2_enabled': 'ssl.version:sslv2',
    'sslv3_enabled': 'ssl.version:sslv3', 
    'tls10_only': 'ssl.version:tlsv1 -ssl.version:tlsv1.1 -ssl.version:tlsv1.2 -ssl.version:tlsv1.3',
    
    # Weak Cipher Suites
    'rc4_ciphers': 'ssl.cipher:"RC4"',
    'des_ciphers': 'ssl.cipher:"DES"',
    'export_ciphers': 'ssl.cipher:"EXPORT"',
    'null_ciphers': 'ssl.cipher:"NULL"',
    
    # Certificate Issues
    'md5_signatures': 'ssl.cert.sig_alg:"md5"',
    'sha1_signatures': 'ssl.cert.sig_alg:"sha1"',
    'weak_dh_params': 'ssl.dh.bits:<1024',
    
    # Perfect Forward Secrecy
    'no_pfs': '-ssl.cipher:"ECDHE" -ssl.cipher:"DHE"'
}
```

### 3. Network Protocol and Service Analysis / Ağ Protokolü ve Servis Analizi

#### Industrial Control Systems (ICS/SCADA) / Endüstriyel Kontrol Sistemleri
```python
# ICS/SCADA specific filters
ics_scada_filters = {
    # Modbus Protocol (Port 502)
    'modbus_devices': 'port:502 country:TR',
    'modbus_schneider': 'port:502 "schneider" country:TR',
    'modbus_siemens': 'port:502 "siemens" country:TR',
    
    # DNP3 Protocol (Port 20000)
    'dnp3_devices': 'port:20000 country:TR',
    
    # IEC 61850 (Port 102)
    'iec61850_devices': 'port:102 country:TR',
    
    # BACnet (Port 47808)
    'bacnet_devices': 'port:47808 country:TR',
    
    # SCADA HMI Interfaces
    'wonderware_hmi': 'port:80 "wonderware" country:TR',
    'ge_cimplicity': 'port:80 "cimplicity" country:TR',
    'rockwell_factorytalk': 'port:80 "factorytalk" country:TR',
    
    # PLC Programming Interfaces
    'siemens_s7': 'port:102 "siemens" country:TR',
    'allen_bradley': 'port:44818 "allen bradley" country:TR',
    'schneider_unity': 'port:502 "unity" country:TR'
}
```

#### Database and Data Store Detection / Veritabanı ve Veri Deposu Tespiti
```python
# Advanced database discovery
database_filters = {
    # Traditional Databases
    'mysql_exposed': 'port:3306 "mysql" -authentication country:TR',
    'postgresql_open': 'port:5432 "postgresql" -authentication country:TR',
    'mssql_exposed': 'port:1433 "microsoft sql server" country:TR',
    'oracle_exposed': 'port:1521 "oracle" country:TR',
    
    # NoSQL Databases
    'mongodb_open': 'port:27017 "mongodb server information" -authentication country:TR',
    'elasticsearch_open': 'port:9200 "elasticsearch" -authentication country:TR',
    'redis_open': 'port:6379 "redis" -authentication country:TR',
    'cassandra_open': 'port:9042 "cassandra" -authentication country:TR',
    'couchdb_open': 'port:5984 "couchdb" -authentication country:TR',
    
    # Big Data Platforms
    'hadoop_namenode': 'port:9000,50070 "hadoop" country:TR',
    'spark_master': 'port:7077,8080 "spark" country:TR',
    'kafka_brokers': 'port:9092 "kafka" country:TR',
    
    # In-Memory Databases
    'memcached_open': 'port:11211 "memcached" country:TR',
    'hazelcast_open': 'port:5701 "hazelcast" country:TR'
}
```

### 4. Cloud and Container Technology Filters / Bulut ve Konteyner Teknoloji Filtreleri

#### Container Orchestration Platforms / Konteyner Orkestrasyon Platformları
```python
# Container and orchestration discovery
container_filters = {
    # Kubernetes
    'k8s_api_server': 'port:6443,8080 "kubernetes" country:TR',
    'k8s_dashboard': 'port:8080 "kubernetes dashboard" country:TR',
    'k8s_etcd': 'port:2379,2380 "etcd" country:TR',
    'k8s_kubelet': 'port:10250,10255 "kubelet" country:TR',
    
    # Docker
    'docker_api': 'port:2375,2376 "docker" country:TR',
    'docker_registry': 'port:5000 "docker-distribution" country:TR',
    'docker_swarm': 'port:2377 "docker swarm" country:TR',
    
    # Container Registries
    'docker_hub_mirror': 'port:5000 "registry" country:TR',
    'harbor_registry': 'port:80,443 "harbor" country:TR',
    'quay_registry': 'port:80,443 "quay" country:TR',
    
    # Service Mesh
    'istio_pilot': 'port:15010 "istio" country:TR',
    'consul_connect': 'port:8500 "consul" country:TR',
    'linkerd_proxy': 'port:4191 "linkerd" country:TR'
}
```

#### Cloud Service Detection / Bulut Servisi Tespiti
```python
# Cloud infrastructure identification
cloud_filters = {
    # AWS Services
    'aws_metadata': 'http.html:"169.254.169.254"',
    'aws_s3_buckets': 'hostname:"s3.amazonaws.com" OR hostname:"s3-"',
    'aws_elb': 'hostname:"elb.amazonaws.com"',
    'aws_cloudfront': 'ssl.cert.issuer.cn:"Amazon"',
    
    # Azure Services  
    'azure_metadata': 'http.html:"169.254.169.254/metadata"',
    'azure_storage': 'hostname:".blob.core.windows.net"',
    'azure_websites': 'hostname:".azurewebsites.net"',
    
    # Google Cloud
    'gcp_metadata': 'http.html:"metadata.google.internal"',
    'gcp_storage': 'hostname:".storage.googleapis.com"',
    'gcp_app_engine': 'hostname:".appspot.com"',
    
    # Turkish Cloud Providers
    'turkcell_bulut': 'hostname:".bulut.com.tr" country:TR',
    'vargonen_cloud': 'hostname:".vargonen.com" country:TR',
    'bbt_bulut': 'hostname:".bbt.gov.tr" country:TR'
}
```

## Advanced Search Techniques / Gelişmiş Arama Teknikleri

### 1. Boolean Logic and Complex Queries / Boolean Mantık ve Karmaşık Sorgular

#### Multi-Condition Filtering / Çoklu Koşul Filtreleme
```python
# Complex boolean search examples
complex_queries = {
    # Vulnerable web servers in Turkey
    'vulnerable_web_turkey': 
        '(apache OR nginx OR iis) AND country:TR AND (vuln:CVE-2021-44228 OR vuln:CVE-2022-22965)',
    
    # Exposed databases with weak authentication
    'weak_auth_databases':
        '(port:3306 OR port:5432 OR port:27017) AND -authentication AND country:TR',
    
    # IoT devices with default credentials
    'default_cred_iot':
        'device:router AND (http.title:"admin" OR http.title:"login") AND country:TR',
    
    # Industrial systems without encryption
    'unencrypted_ics':
        '(port:502 OR port:102 OR port:20000) AND -ssl AND country:TR',
    
    # Cloud instances with exposed services
    'exposed_cloud_services':
        '(hostname:".amazonaws.com" OR hostname:".azure.com" OR hostname:".googlecloud.com") '
        'AND (port:22 OR port:3389 OR port:5432)'
}
```

#### Regular Expression Patterns / Düzenli İfade Kalıpları
```python
# Advanced regex patterns for Shodan
regex_patterns = {
    # Version number extraction
    'apache_versions': r