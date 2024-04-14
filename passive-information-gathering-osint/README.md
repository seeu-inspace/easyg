# Passive Information Gathering (OSINT)

## Index

- [Notes](#notes)
- [Tools](#tools)
- [Target validation](#target-validation)
- [User Information Gathering](#user-information-gathering)
  - [Email Harvesting](#email-harvesting)
  - [Social media tools](#social-media-tools)
  - [Data breaches](#data-breaches)
  - [Acquisitions](#acquisitions)

## Notes
- [ ] Target validation
- [ ] Search for email addresses of employees
  - What's the format? Does it change for founders, chief officers etc.?
- [ ] Search for corporate social media accounts
- [ ] Use [whois](https://who.is/)
  - `whois targetcorp.com`
- [ ] [Google Dorking](#google-dorking)
  - Start searching for PHP files and directory listing
- [ ] Search for any company acquisitions of the target
- [ ] See also [Content Discovery](#content-discovery)
- [ ] See each section of this chapter

## Tools

- [Stack Overflow](https://stackoverflow.com/)
- [Information Gathering Frameworks](https://osintframework.com/)
- [Maltego](https://www.maltego.com/)
- [bgp.he.net](https://bgp.he.net/)
- [Crunchbase](https://www.crunchbase.com/)
- [OCCRP Aleph](https://aleph.occrp.org/)

## Target validation

- Use `WHOIS`, `nslookup` and `dnsrecon`
- [searchdns.netcraft.com](https://searchdns.netcraft.com/)
  - Search for registration information and site technology entries
- [Recon-ng](https://github.com/lanmaster53/recon-ng)
  - ```
    marketplace search github                                      Search the Marketplace for GitHub modules
    marketplace info recon/domains-hosts/google_site_web           Get information on a module
    marketplace install recon/domains-hosts/google_site_web        Install a module
    modules load recon/domains-hosts/google_site_web               Load a module
    info                                                           Get infos about module loaded
    options set SOURCE targetcorp.com                              Set a source
    run                                                            Run a module
    back                                                           Get  back to default
    show                                                           Show the results; hosts, companies, leaks etc.
    ```
  - Use `recon/domains-hosts/google_site_web` combined with `recon/hosts-hosts/resolve`
- Passively search for information in open-source projects and online code repositories.
  - [GitHub Dorking](#github-dorking)
  - [Gitrob](https://github.com/michenriksen/gitrob)
  - [Gitleaks](https://github.com/gitleaks/gitleaks)
  - [Source code review](#source-code-review)
- [Shodan](https://www.shodan.io/)
  ```
  hostname:targetcorp.com                  Search for TargetCorp’s domain
  hostname:targetcorp.com port:'22'        Search for TargetCorp’s domain running SSH
  ```
  - [Shodan for Chrome](https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap) and [for Firefox](https://addons.mozilla.org/en-US/firefox/addon/shodan_io/)
- [Security Headers Scanner](https://securityheaders.com/)
- [SSL Server Test](https://www.ssllabs.com/ssltest/)
- [DMARC Inspector](https://dmarcian.com/dmarc-inspector/)

## User Information Gathering

Note: A company may only approve tests of its own systems. Personal devices, outside email, and social media accounts used by employees often do not come under this authorisation.

### Email Harvesting

- [theHarvester](https://github.com/laramies/theHarvester)
  ```
  theharvester -d targetcorp.com -b google                  -d specify target domain, -b set data source to search
  ```
- [hunter.io](https://hunter.io/)
- [Phonebook.cz](https://phonebook.cz/)
- [voilanorbert.com](https://www.voilanorbert.com/)
- [Clearbit](https://clearbit.com/)

Verify email addresses
- [Email Hippo](https://tools.emailhippo.com/)
- [Email Checker](https://email-checker.net/)

### Social media tools

- [Social Searcher](https://www.social-searcher.com/)
- [Twofi](https://digi.ninja/projects/twofi.php)
- [linkedin2username](https://github.com/initstring/linkedin2username)


### Data breaches

- [HaveIBeenPwned](https://haveibeenpwned.com/)
- [Breach-Parse](https://github.com/hmaverickadams/breach-parse)
- [WeLeakInfo](https://mobile.twitter.com/weleakinfo)
- [Dehashed](https://www.dehashed.com/)
  - [Hashes.com](https://hashes.com/en/decrypt/hash)

Malicious hackers frequently post stolen passwords on [Pastebin](https://pastebin.com/) or other less reputable websites. This is useful for generating wordlists.
- An example: [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)

### Acquisitions

Search for any acquisitions by the target
- [bgp.he.net](https://bgp.he.net/)
- [Crunchbase](https://www.crunchbase.com/)
- [OCCRP Aleph](https://aleph.occrp.org/)
