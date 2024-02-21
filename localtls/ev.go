package localtls

// The EV Object Identifier List Supported by Firefox
// Browse to: https://searchfox.org/mozilla-central/source/security/certverifier/ExtendedValidation.cpp and the
// https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReport CA Certificate Report for Mozilla and
// use the extracted EV Policy OID(s)
// The map below contains the string version of ASN.1. EV OIDs mapped to the issuing entity.

var EVObjectIdentifiers = map[string]string{
	"1.3.6.1.4.1.13769.666.666.666.1.500.9.1": "DEBUGtesting EV OID",

	// CN=SwissSign Gold CA - G2,O=SwissSign AG,C=CH
	"2.16.756.1.89.1.2.1.1": "SwissSign EV OID",

	// CN=XRamp Global Certification Authority,O=XRamp Security Services Inc,OU=www.xrampsecurity.com,C=US
	// CN=SecureTrust CA,O=SecureTrust Corporation,C=US
	// CN=Secure Global CA,O=SecureTrust Corporation,C=US
	"2.16.840.1.114404.1.1.2.4.1": "Trustwave EV OID",

	// CN=COMODO ECC Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
	// CN=COMODO Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
	// CN=COMODO RSA Certification Authority,O=COMODO CA Limited,L=Salford,ST=Greater Manchester,C=GB
	// CN=USERTrust RSA Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
	// CN=USERTrust ECC Certification Authority,O=The USERTRUST Network,L=Jersey City,ST=New Jersey,C=US
	"1.3.6.1.4.1.6449.1.2.1.5.1": "Comodo EV OID",

	// OU=Go Daddy Class 2 Certification Authority,O=\"The Go Daddy Group, Inc.\",C=US
	// CN=Go Daddy Root Certificate Authority - G2,O="GoDaddy.com, Inc.",L=Scottsdale,ST=Arizona,C=US
	"2.16.840.1.114413.1.7.23.3": "Go Daddy EV OID a",

	// OU=Starfield Class 2 Certification Authority,O=\"Starfield Technologies, Inc.\",C=US
	// CN=Starfield Root Certificate Authority - G2,O="Starfield Technologies, Inc.",L=Scottsdale,ST=Arizona,C=US
	"2.16.840.1.114414.1.7.23.3": "Go Daddy EV OID b",

	// CN=DigiCert High Assurance EV Root CA,OU=www.digicert.com,O=DigiCert Inc,C=US
	// CN=DigiCert Assured ID Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
	// CN=DigiCert Assured ID Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
	// CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
	// CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US
	// CN=DigiCert Trusted Root G4,OU=www.digicert.com,O=DigiCert Inc,C=US
	"2.16.840.1.114412.2.1": "DigiCert EV OID",

	// CN=QuoVadis Root CA 2,O=QuoVadis Limited,C=BM
	// CN=QuoVadis Root CA 2 G3,O=QuoVadis Limited,C=BM
	"1.3.6.1.4.1.8024.0.2.100.1.2": "Quo Vadis EV OID",

	// CN=Entrust Root Certification Authority,OU="(c) 2006 Entrust, Inc.",OU=www.entrust.net/CPS is incorporated by reference,O="Entrust, Inc.",C=US
	// CN=Entrust Root Certification Authority - G4,OU="(c) 2015 Entrust, Inc. - for authorized use only",OU=See www.entrust.net/legal-terms,O="Entrust, Inc.",C=US
	// CN=Entrust.net Certification Authority (2048),OU=(c) 1999 Entrust.net Limited,OU=www.entrust.net/CPS_2048 incorp. by ref. (limits liab.),O=Entrust.net
	// CN=Entrust Root Certification Authority - G2,OU="(c) 2009 Entrust, Inc. - for authorized use only",OU=See www.entrust.net/legal-terms,O="Entrust, Inc.",C=US
	// CN=Entrust Root Certification Authority - EC1,OU="(c) 2012 Entrust, Inc. - for authorized use only",OU=See www.entrust.net/legal-terms,O="Entrust, Inc.",C=US
	"2.16.840.1.114028.10.1.2": "Entrust EV OID",

	// CN=GlobalSign Root CA,OU=Root CA,O=GlobalSign nv-sa,C=BE
	// CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R3
	// CN=DigiCert TLS RSA4096 Root G5,O="DigiCert, Inc.",C=US
	// CN=DigiCert TLS ECC P384 Root G5,O="DigiCert, Inc.",C=US
	// CN=GlobalSign,O=GlobalSign,OU=GlobalSign ECC Root CA - R5
	// CN=GlobalSign,O=GlobalSign,OU=GlobalSign Root CA - R6
	// CN=Amazon Root CA 1,O=Amazon,C=US
	// CN=Amazon Root CA 2,O=Amazon,C=US
	// CN=Amazon Root CA 3,O=Amazon,C=US
	// CN=Amazon Root CA 4,O=Amazon,C=US
	// CN=Starfield Services Root Certificate Authority - G2,O="Starfield Technologies, Inc.",L=Scottsdale,ST=Arizona,C=US
	// CN=SSL.com EV Root Certification Authority ECC,O=SSL Corporation,L=Houston,ST=Texas,C=US
	// CN=SSL.com EV Root Certification Authority RSA R2,O=SSL Corporation,L=Houston,ST=Texas,C=US
	// CN=SSL.com TLS ECC Root CA 2022,O=SSL Corporation,C=US
	// CN=SSL.com TLS RSA Root CA 2022,O=SSL Corporation,C=US
	// CN=UCA Extended Validation Root,O=UniTrust,C=CN
	// CN=Hongkong Post Root CA 3,O=Hongkong Post,L=Hong Kong,ST=Hong Kong,C=HK
	// CN=emSign Root CA - G1,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN
	// CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN
	// CN=emSign Root CA - C1,O=eMudhra Inc,OU=emSign PKI,C=US
	// CN=emSign ECC Root CA - C3,O=eMudhra Inc,OU=emSign PKI,C=US
	// OU=certSIGN ROOT CA G2,O=CERTSIGN SA,C=RO
	// CN=IdenTrust Commercial Root CA 1,O=IdenTrust,C=US
	// CN=Trustwave Global Certification Authority,O="Trustwave Holdings, Inc.",L=Chicago,ST=Illinois,C=US
	// CN=Trustwave Global ECC P256 Certification Authority,O="Trustwave Holdings, Inc.",L=Chicago,ST=Illinois,C=US
	// CN=Trustwave Global ECC P384 Certification Authority,O="Trustwave Holdings, Inc.",L=Chicago,ST=Illinois,C=US
	// CN=GlobalSign Root R46,O=GlobalSign nv-sa,C=BE
	// CN=GlobalSign Root E46,O=GlobalSign nv-sa,C=BE
	// "CN=AC RAIZ FNMT-RCM SERVIDORES SEGUROS,OID.2.5.4.97=VATES-Q2826004J,OU=Ceres,O=FNMT-RCM,C=E
	// CN=GLOBALTRUST 2020,O=e-commerce monitoring GmbH,C=AT
	// CN=Certum Extended Validation ECC CA,OU=Certum Certification Authority,O=Asseco Data Systems S.A.,C=PL
	// CN=Certum Extended Validation RSA CA,OU=Certum Certification Authority,O=Asseco Data Systems S.A.,C=PL
	// CN=ANF Secure Server Root CA,OU=ANF CA Raiz,O=ANF Autoridad de Certificacion,C=ES,serialNumber=G63287510
	// CN=Hellenic Academic and Research Institutions ECC RootCA 2015,O=Hellenic Academic and Research Institutions Cert. Authority,L=Athens,C=GR
	// CN=Hellenic Academic and Research Institutions RootCA 2015,O=Hellenic Academic and Research Institutions Cert. Authority,L=Athens,C=GR
	// CN=HARICA TLS RSA Root CA 2021,O=Hellenic Academic and Research Institutions CA,C=GR
	// CN=HARICA TLS ECC Root CA 2021,O=Hellenic Academic and Research Institutions CA,C=GR
	// CN=vTrus Root CA,O="iTrusChina Co.,Ltd.",C=CN
	// CN=vTrus ECC Root CA,O="iTrusChina Co.,Ltd.",C=CN
	// CN=Autoridad de Certificacion Firmaprofesional CIF A62634068,C=ES
	// CN=NetLock Arany (Class Gold) Főtanúsítvány,OU=Tanúsítványkiadók (Certification Services),O=NetLock Kft.,L=Budapest,C=HU
	// CN=D-TRUST EV Root CA 1 2020,O=D-Trust GmbH,C=DE
	// CN=BJCA Global Root CA1,O=BEIJING CERTIFICATE AUTHORITY,C=CN
	// CN=BJCA Global Root CA2,O=BEIJING CERTIFICATE AUTHORITY,C=CN
	// CN=Sectigo Public Server Authentication Root E46,O=Sectigo Limited,C=GB
	// CN=Sectigo Public Server Authentication Root R46,O=Sectigo Limited,C=GB
	"2.23.140.1.1": "CA/Browser Forum EV OID",

	// CN=Buypass Class 3 Root CA,O=Buypass AS-983163327,C=NO
	"2.16.578.1.26.1.3.3": "Buypass EV OID",

	// CN=AffirmTrust Commercial,O=AffirmTrust,C=US
	"1.3.6.1.4.1.34697.2.1": "AffirmTrust EV OID a",

	// CN=AffirmTrust Networking,O=AffirmTrust,C=US
	"1.3.6.1.4.1.34697.2.2": "AffirmTrust EV OID b",

	// CN=AffirmTrust Premium,O=AffirmTrust,C=US
	"1.3.6.1.4.1.34697.2.3": "AffirmTrust EV OID c",

	// CN=AffirmTrust Premium ECC,O=AffirmTrust,C=US
	"1.3.6.1.4.1.34697.2.4": "AffirmTrust EV OID d",

	// CN=Certum Trusted Network CA,OU=Certum Certification Authority,O=Unizeto Technologies S.A.,C=PL
	// CN=Certum Trusted Network CA 2,OU=Certum Certification Authority,O=Unizeto Technologies S.A.,C=PL
	"1.2.616.1.113527.2.5.1.1": "Certum EV OID",

	// CN=Izenpe.com,O=IZENPE S.A.,C=ES
	"1.3.6.1.4.1.14777.6.1.1": "Izenpe EV OID 1",

	// CN=Izenpe.com,O=IZENPE S.A.,C=ES
	"1.3.6.1.4.1.14777.6.1.2": "Izenpe EV OID 2",

	// CN=T-TeleSec GlobalRoot Class 3,OU=T-Systems Trust Center,O=T-Systems Enterprise Services GmbH,C=DE
	"1.3.6.1.4.1.7879.13.24.1": "T-Systems EV OID",

	// CN=TWCA Root Certification Authority,OU=Root CA,O=TAIWAN-CA,C=TW
	// CN = TWCA Global Root CA, OU = Root CA, O = TAIWAN-CA, C = TW
	"1.3.6.1.4.1.40869.1.1.22.3": "TWCA EV OID",

	// CN=D-TRUST Root Class 3 CA 2 EV 2009,O=D-Trust GmbH,C=DE
	"1.3.6.1.4.1.4788.2.202.1": "D-TRUST EV OID",

	// CN = Autoridad de Certificacion Firmaprofesional CIF A62634068, C = ES
	"1.3.6.1.4.1.13177.10.1.3.10": "Firmaprofesional EV OID",

	// CN=Actalis Authentication Root CA,O=Actalis S.p.A./03358520967,L=Milan,C=IT
	"1.3.159.1.17.1": "Actalis EV OID",

	// CN=CFCA EV ROOT,O=China Financial Certification Authority,C=CN
	"2.16.156.112554.3": "CFCA EV OID",

	// OU=Security Communication RootCA2,O="SECOM Trust Systems CO.,LTD.",C=JP
	"1.2.392.200091.100.721.1": "SECOM EV OID",

	// CN=OISTE WISeKey Global Root GB CA,OU=OISTE Foundation Endorsed,O=WISeKey,C=CH
	"2.16.756.5.14.7.4.8": "WISeKey EV OID",

	// CN=GDCA TrustAUTH R5 ROOT,O="GUANG DONG CERTIFICATE AUTHORITY CO.,LTD.",C=CN
	"1.2.156.112559.1.1.6.1": "GDCA EV OID",

	// https://cabforum.org/object-registry/
	"2.23.140.1.3": "CA/Browser Forum EV OID - Code Signing",
}
