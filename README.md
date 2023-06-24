# DNS Analyzer
A Burp Suite extension for discovering DNS vulnerabilities in web applications!  
*An in-depth guide for the DNS Analyzer can be found [here](https://r.sec-consult.com/dnsburp).*  
## Install (Coming soon!)

~~*The DNS Analyzer extension can be installed directly from the BApp Store in Burp Suite!  
```Extensions > BApp Store > DNS Analyzer```*~~

## Compile & Install
You can download the precompiled JAR from [releases](https://github.com/The-Login/DNS-Analyzer/releases/tag/v1.0).  
**Or**, you can build this project via the ```fatJar``` gradle task:  
- Linux: ```./gradlew fatJar```  
- Windows: ```gradlew.bat fatJar```  

The compiled JAR can then be found under ```build/libs/```.  

To load the extension via Burp Suite Professional, navigate to ```Extensions > Installed > Add``` and select
```DNSAnalyzer-all-1.0.jar``` as .jar file.

## Howto
The basic usage boils down to the following steps:  
1. Click "Copy to Clipboard" to generate and copy a Burp Collaborator domain
2. Get something to resolve the generated domain via DNS. For example, by using it:
   - as an e-mail domain (e.g., test@[collaborator domain])
      - Use it at registrations
      - Use it at password resets
      - Use it for news-letters
      - ...
   - via SSRF
   - anywhere, where the collaborator domain gets resolved via DNS
3. Analyze the DNS name resolution by selecting DNS messages in the table
4. ...
5. Profit

Here's an example overview of this process:  
![DNS Analyzer Overview_small](https://github.com/The-Login/DNS-Analyzer/assets/84237895/91fc4496-f55f-483a-8b9a-7738ae45f8c7)  
Advanced usage and more can be found [here](https://r.sec-consult.com/dnsburp).
## Bug Bounty Tips
Should you be looking for DNS vulnerabilities in bug bounty domains?  
**YES!** However, only report a DNS vulnerability if:  
1. infrastructure is in the scope of the bug bounty program
2. you've confirmed the vulnerability via in-depth DNS analysis (e.g., via the [DNS Analysis Server](https://github.com/The-Login/DNS-Analysis-Server))  

Essentially, **don't flood bug bounty programs with DNS vulnerability reports without doing proper research first!**
## Further Info
As already mentioned, you can find a full DNS Analyzer guide [here](https://r.sec-consult.com/dnsburp).  
Also, you can find further information about DNS analysis and DNS vulnerabilities in the following blog posts:  
- [First blog post](https://sec-consult.com/blog/detail/forgot-password-taking-over-user-accounts-kaminsky-style/) showing the basics of DNS analysis in web applications
- [Second blog post](https://sec-consult.com/blog/detail/melting-the-dns-iceberg-taking-over-your-infrastructure-kaminsky-style/) showing further DNS analysis methods and exploitation  

Also, the Collaborator server has it's limits. For in-depth DNS analysis you can use the [DNS Analysis Server](https://github.com/The-Login/DNS-Analysis-Server).
