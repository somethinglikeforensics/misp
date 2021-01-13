class CONST:
    MISP_URL=r'<MISP_URL_HERE>'    
    MISP_KEY=r'<MISP_KEY_KEY>'
    MISP_VERIFY_CERT=False
    MISP_CLIENT_CERT = ''
    OTX_KEY=r'<OTX_KEY_HERE'
    
    NETWORK_INDICATORS = ["ip-dst", "domain", "hostname", "url"]
    
    # otx type : misp type
    TYPE_LOOKUP = {    
                    "IPV4": "ip-dst",
                    "IPV6": "ip-dst",
                    "DOMAIN": "domain",
                    "HOSTNAME": "hostname",
                    "URL": "url",
                    "FILEHASH-MD5": "md5",
                    "FILEHASH_MD5": "md5",
                    "FILE_HASH_MD5": "md5",
                    
                    "FILEHASH-SHA1": "sha1",
                    "FILE_HASH_SHA1": "sha1",
                    "FILEHASH_SHA1": "sha1",
                    
                    "FILEHASH-SHA256": "sha256",
                    "FILE_HASH_SHA256": "sha256",
                    "FILEHASH_SHA256": "sha256",
                    "CVE": "vulnerability",
                    "EMAIL" : "email-src"
                    }




