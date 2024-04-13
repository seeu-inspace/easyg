## Source code review

- Search for known dangerous functions used on user-supplied input
  - example, `eval(` can cause command injection without proper sanitization
- Search for hardcoded credentials such as API keys, encryption keys and database passwords
  - many API keys start with the same format (ex. AWS keys usually start with `AKIA`), search for patterns
    <img src="img/Screenshot_20221110_171255.png">
	from [ServletTarPit.java](https://github.com/ShiftLeftSecurity/tarpit-java/blob/master/src/main/java/io/shiftleft/tarpit/ServletTarPit.java), [Tarpit Java](https://github.com/ShiftLeftSecurity/tarpit-java)
- Search for weak cryptography or hashing algorithms
- Search for outdated dependencies
- Search for revealing comments
- Just because there is a dangerous function, doesn’t mean that there is a vulnerability
- If a parameter is not filtered / escaped, then it’s better to check the function that accepts it
- If there is something like `filtering_or_escaping`, you should check the quality of it for any bypass

**Strategies**
There are many methods to do code review. Some examples:
- Bottom up / Bottom down where you start from the functions you encounter first and see which other functions it calls and which other functions are called from
- Greb way, where you search for specific keys like file.open, system, eval. This way is useful only if you want to do a quick code review
- Another way is to start from a functionality, like Password Reset, and review all the code linked to this function. I’ll review which function Password Reset calls and by wich function, it’s called.

**Digging deeeper**
- Prioritize functions like authentication, autorization, PII etc.
  - example: disclosing PII in the logs, from [OrderStatus.java](https://github.com/ShiftLeftSecurity/tarpit-java/blob/master/src/main/java/io/shiftleft/tarpit/OrderStatus.java)
    <img src="img/Screenshot_20221110_172648.png">
  - example: SQL injection in [OrderStatus.java](https://github.com/ShiftLeftSecurity/tarpit-java/blob/master/src/main/java/io/shiftleft/tarpit/OrderStatus.java)
    <img src="img/Screenshot_20221110_173028.png">
- Follow any code that deals with user input

**URL routing**

- `On “Ruby on rails” we have `config/routes.rb` and a directory `app/controllers/…`. Something similar happens for applications like “struts” where the configuration is in an xml file.
- Another example is “Python Flask” where the mapping is part of the source code and you might encounter something like `@app.route(’hello’)\ndef hello:\n…` . Same will happen with “Ruby Sinatra” with something like `get hello do\n …\nend`.


**Check-list**

1. Do you see a function that contains dangerous code?
   - ⇒ No. Move on
   - ⇒ Yes. Next check.
2. Do you have control over interesting arguments?
   - ⇒ No. move on
   - ⇒ Yes. Next check.
3. There are any filtering in place? 
   - ⇒ No. Vulnerability.
   - ⇒ Yes. Next check.
4. The filters are sufficient?
   - ⇒ Yes. Weakness (vulnerability that it might not be exploitable now but maybe one day)
   - ⇒ No. Next check.
5. It’s the code reachable?
   - ⇒ No. Weakness (vulnerability that it might not be exploitable now but maybe one day)
   - ⇒ Yes. Vulnerability
   - ⇒ Yes, but with more filtering. Go back to check 4.

**Filtering / Escaping**

- **No Filtering/Escaping**
- **Naive Filtering/Escaping**
    - Just blocking common payloads like `' or 1=1 —`
    - Blocking spaces for SQL injections
    - Blocking `alerts()`
    - Blocking `<script>` tags
    - Blocking `phpinfo()` for code execution
- **Incomplete Filtering/Escaping**
    - Not escaping single quotes for XSS
    - No parameterized on LIMIT or ORDER for SQL injections
    - Only filtering “&”, “;” and “|” for command execution
    - Only escaping “none” and forgetting “None” for JWT algorithm
- **Non Recursive Filtering/Escaping**
    - The filter removes “…/” in a path ⇒ “../../../test” becomes “test” ⇒ “….//….//….//test” becomes “../../../test”
- **Non Context Aware Recursive Filtering/Escaping**
    - If the valued is echoed in HTML code vs JavaScript
    - Escaping of a path Linux vs Windows
- **Regular Expressions**
    - Missing “^” (caret) and/or “$” to enforce the start or end of the line.
        - `/^pentesterlab/` will match `pentesterlab.com.example.org`.
        - Matching one word, `/\w+$/` will match `../../../../webshell.ph`p ⇒ it should be `/^\w+$/`
        - The same applies for functions startwith and endwith
    - Not escaping special characters
        - `/^assets.pentesterlab.com$/`, the dot is not escaped so it will match `[assetszpentesterlab.com](http://assetszpentesterlab.com)` ⇒ the correct way is `/^assets\.pentesterlab\.com$/`
    - Some languages use multiline by default, in Ruby, for example:
        - `/^test$/` will match “test\nHACKER” ⇒ the correct way is `/\Atest\z/`
        - Other languares use “m” at the end to specify multiline like `/^test$/m` so make sure it’s not used
        - Ignorecase: `/^inc$/i` will match “ınc**”,** dotless i (in Turkish), remove the ignorecase
- **Modifications before or after Filtering/Escaping**
    - Check again that the modifications does not create another exploitation

**Automation**
- Use SAST tools
- Use SCA tools
- Use secret scanners
- Then test the results manually

**Resources**
- [How to Analyze Code for Vulnerabilities](https://www.youtube.com/watch?v=A8CNysN-lOM)
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)

**Tools**
- [Visual Studio Code](https://code.visualstudio.com/) for Source Code Analysis
- [beautifier.io](https://beautifier.io/) for JavaScript Analysis
- [DNSpy](https://github.com/dnSpy/dnSpy), .NET debugger
- [Rider](https://www.jetbrains.com/rider/download/#section=windows)
- [Tarpit Java](https://github.com/ShiftLeftSecurity/tarpit-java)
- [TruffleHog](https://github.com/trufflesecurity/trufflehog)
- [GitLeaks](https://github.com/zricethezav/gitleaks)

**Some grep**
- Quickly discover XSS vulnerabilities in PHP files `rg --no-heading "echo.*\\\$_GET" | grep "\.php:" | grep -v -e "(\$_GET" -e "( \$_GET" -e "esc_" -e "admin_url" -e "(int)" -e htmlentities` [[source](https://twitter.com/hakluke/status/1757661414762635610)]
