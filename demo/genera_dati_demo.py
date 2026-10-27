"""Genera DATI SINTETICI per provare SovraSBOM senza una VM.

ATTENZIONE: componenti, versioni e vulnerabilita' (CVE-DEMO-xxxx) sono INVENTATI e
ricalcano solo la struttura di un server Zimbra. Servono per provare il tool e la
presentazione, NON vanno presentati come risultati reali.

Uso:  python3 demo/genera_dati_demo.py   (crea i file nella cartella corrente)
"""
import json, random
random.seed(7)
comps=[]
def add(name, ver, ptype, ns, lic, pub, syft_type, path, hashed=False):
    purl=f"pkg:{ptype}/{ns+'/' if ns else ''}{name}@{ver}" if ptype else ""
    c={"bom-ref":f"ref-{len(comps)}","type":"library","name":name,"version":ver}
    if pub: c["publisher"]=pub
    if purl: c["purl"]=purl
    if lic: c["licenses"]=[{"license":{"id":lic}} if " " not in lic else {"expression":lic}]
    if hashed: c["hashes"]=[{"alg":"SHA-256","content":"ab"*32}]
    c["properties"]=[{"name":"syft:package:type","value":syft_type},{"name":"syft:location:0:path","value":path}]
    comps.append(c)
# deb di sistema
for n,v,l in [("openssl","3.0.13-0ubuntu3.4","Apache-2.0"),("libc6","2.39-0ubuntu8.3","LGPL-2.1"),("bash","5.2.21-2ubuntu4","GPL-3.0"),
              ("libxml2","2.9.14+dfsg-1.3ubuntu3","MIT"),("zlib1g","1:1.3.dfsg-3.1ubuntu2","Zlib"),("perl","5.38.2-3.2build2","Artistic-1.0 OR GPL-1.0"),
              ("libcurl4t64","8.5.0-2ubuntu10.4","curl"),("libsqlite3-0","3.45.1-1ubuntu2","public-domain"),("libaio1t64","0.3.113-6build1",""),("libpcre3","2:8.39-15build1","BSD-3-Clause")]:
    add(n,v,"deb","ubuntu",l,"Ubuntu Developers","deb","/var/lib/dpkg/status")
for i in range(40):
    add(f"lib-sys-{i}", f"1.{i}.0-1ubuntu1","deb","ubuntu",random.choice(["GPL-2.0","LGPL-2.1","MIT","BSD-3-Clause",""]),"Ubuntu Developers","deb","/var/lib/dpkg/status")
# pacchetti zimbra (repo zimbra)
for n,v,l in [("zimbra-openssl","3.0.9-1zimbra8.8b1","Apache-2.0"),("zimbra-openjdk","17.0.10-1zimbra8.8b1","GPL-2.0 WITH Classpath-exception-2.0"),
              ("zimbra-nginx","1.20.0-1zimbra8.8b5",""),("zimbra-postfix","3.6.14-1zimbra8.7b4","IPL-1.0"),("zimbra-openldap","2.5.17-1zimbra10.0b1",""),
              ("zimbra-mariadb","10.6.14-1zimbra8.8b6","GPL-2.0")]:
    add(n,v,"deb","zimbra",l,"Zimbra Packaging Services","deb","/var/lib/dpkg/status")
# binari incorporati
add("openssl","3.0.9","generic","", "", "", "binary","/opt/zimbra/common/bin/openssl")
add("java","17.0.10","generic","", "", "", "binary","/opt/zimbra/common/lib/jvm/java/bin/java")
add("nginx","1.20.0","generic","","","","binary","/opt/zimbra/common/sbin/nginx")
# jar
for n,ns,v,l in [("jetty-server","org.eclipse.jetty","9.4.46.v20220331","Apache-2.0 OR EPL-1.0"),("log4j-core","org.apache.logging.log4j","2.17.1","Apache-2.0"),
                 ("commons-text","org.apache.commons","1.9","Apache-2.0"),("guava","com.google.guava","28.0-jre","Apache-2.0"),("jackson-databind","com.fasterxml.jackson.core","2.13.2","Apache-2.0"),
                 ("zm-mailbox","","10.1.18",""),("zm-store","","10.1.18",""),("bcprov-jdk15on","org.bouncycastle","1.64","MIT"),("commons-fileupload","commons-fileupload","1.4","Apache-2.0"),
                 ("guava","com.google.guava","31.1-jre","Apache-2.0"),("jackson-databind","com.fasterxml.jackson.core","2.15.2","Apache-2.0")]:
    add(n,v,"maven",ns,l,"",  "java-archive",f"/opt/zimbra/jetty_base/webapps/service/WEB-INF/lib/{n}-{v}.jar",hashed=True)
for i in range(60):
    add(f"zm-lib-{i}", f"10.1.{i%5}", "maven", "" if i%3==0 else "com.zimbra", "" if i%4==0 else random.choice(["Apache-2.0","GPL-2.0","MIT","Zimbra-EULA"]), "", "java-archive", f"/opt/zimbra/lib/jars/zm-lib-{i}.jar", hashed=True)
for i in range(15):
    add(f"Zimbra::Perl{i}", f"0.{i}", "cpan","", random.choice(["Artistic-1.0 OR GPL-1.0","",""]), "", "perl", f"/opt/zimbra/common/lib/perl5/Mod{i}.pm")
sbom={"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2026-10-26T15:00:00Z","tools":{"components":[{"name":"syft","version":"1.x-demo"}]},"component":{"name":"/opt/zimbra"}},
      "components":comps,"dependencies":[]}
json.dump(sbom,open("demo-sbom.cdx.json","w"),indent=1)
# grype
def match(vid,sev,name,ver,typ,fix,cvss,epss=None,kev=False):
    v={"id":vid,"severity":sev,"fix":{"versions":[fix] if fix else [],"state":"fixed" if fix else "not-fixed"},"cvss":[{"metrics":{"baseScore":cvss}}],"description":"Demo"}
    if epss is not None: v["epss"]=[{"cve":vid,"epss":epss,"percentile":0.9}]
    if kev: v["knownExploited"]=[{"cve":vid}]
    return {"vulnerability":v,"artifact":{"name":name,"version":ver,"type":typ},"relatedVulnerabilities":[]}
ms=[match("CVE-DEMO-0001","Critical","log4j-core","2.17.1","java-archive","2.17.2",9.8,0.62,True),
    match("CVE-DEMO-0002","High","jetty-server","9.4.46.v20220331","java-archive","9.4.54",7.5,0.21),
    match("CVE-DEMO-0003","Critical","commons-text","1.9","java-archive","1.10.0",9.8,0.44,True),
    match("CVE-DEMO-0004","High","openssl","3.0.9","binary","3.0.15",7.5,0.03),
    match("CVE-DEMO-0005","Medium","openssl","3.0.9","binary","3.0.14",5.9,0.01),
    match("CVE-DEMO-0006","High","zimbra-nginx","1.20.0-1zimbra8.8b5","deb","",7.7,0.02),
    match("CVE-DEMO-0007","Medium","guava","28.0-jre","java-archive","32.0.0",5.5,0.001),
    match("CVE-DEMO-0008","High","jackson-databind","2.13.2","java-archive","2.13.4.2",7.5,0.05),
    match("CVE-DEMO-0009","Critical","bcprov-jdk15on","1.64","java-archive","1.78",9.1,0.004),
    match("CVE-DEMO-0010","High","commons-fileupload","1.4","java-archive","1.5",7.5,0.12),
    match("CVE-DEMO-0011","Low","libxml2","2.9.14+dfsg-1.3ubuntu3","deb","",3.3,0.0005),
    match("CVE-DEMO-0012","Medium","libcurl4t64","8.5.0-2ubuntu10.4","deb","8.5.0-2ubuntu10.5",6.5,0.002),
    match("CVE-DEMO-0013","High","java","17.0.10","binary","17.0.12",7.4,0.01),
    match("CVE-DEMO-0014","Medium","zimbra-postfix","3.6.14-1zimbra8.7b4","deb","",5.3,0.004),
    match("CVE-DEMO-0015","Negligible","bash","5.2.21-2ubuntu4","deb","",2.0,0.0001),
    ]
for i in range(30):
    ms.append(match(f"CVE-DEMO-1{i:03d}",random.choice(["Medium","Low","High","Medium"]),"zm-lib-%d"%(i%12),"10.1.%d"%((i%12)%5),"java-archive",random.choice(["","10.1.20"]),random.uniform(3,8),random.uniform(0,0.05)))
json.dump({"matches":ms},open("demo-grype.json","w"),indent=1)
# vendor sbom (SPDX) incompleta
pk=[]
for c in comps[:120]:
    if c["name"].startswith("Zimbra::"): continue
    ver=c["version"]
    if c["name"]=="jetty-server": ver="9.4.54.v20240208"
    if c["name"]=="log4j-core": ver="2.20.0"
    p={"SPDXID":"SPDXRef-"+c["bom-ref"],"name":c["name"],"versionInfo":ver,"supplier":"Organization: Synacor","licenseConcluded":"NOASSERTION"}
    pk.append(p)
pk.append({"SPDXID":"SPDXRef-x","name":"legacy-connector","versionInfo":"1.0","supplier":"NOASSERTION"})
json.dump({"spdxVersion":"SPDX-2.3","name":"Zimbra vendor","creationInfo":{"created":"2026-08-01T00:00:00Z","creators":["Tool: vendor-gen"]},"packages":pk,"relationships":[]},open("demo-vendor.spdx.json","w"),indent=1)
print(len(comps), len(ms), len(pk))
