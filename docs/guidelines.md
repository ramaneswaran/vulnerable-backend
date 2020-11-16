# Developer Documentation 

This document is a guide for developers to prevent vulnerabilities in their application

## Table Of Contents

* [SQL Injection](#sqli)
    * [Input Validation](#inputval)
    * [Escaping](#escape)
    * [Parameterized Statements](#parameterize)
    * [Object Relation Mapping Frameworks](#orm)
    * [Avoid admininstrative priviliges](#admin)
* [Cross Site Scripting](#xss)
    * [DOM Manipulation](#innerhtml)
* [References](#references)

## Abstract

The world today is making rapid strides towards digitization and businesses are moving their operations online. Web Application vulnerabilities are into existence since the beginning of the internet and the world-wide web. In recent years, it has been given more importance considering the rapid expansion of online presence of critical businesses. Securing these applications is a growing concern as malicious attackers can exploit bugs in these softwares causing a breach of data or potentially halting the application. 

With hackers aimed to exploit this security using various attacks, we are focusing on maintaining XSS attacks, Broken Authentication, Cookie Poisoning,Phishing and Sql Injection. SQL injection attack is a very common attack that manipulates the data passing through web applications to the database servers through web servers in such a way that it alters or reveals database contents. 

<a name="sqli" />

## SQL Injection

A SQL injection attack consists of insertion or “injection” of a SQL query via the input data from the client to the application. SQL injection attacks allow attackers to spoof identity, tamper with existing data, cause repudiation issues such as voiding transactions or changing balances, allow the complete disclosure of all data on the system, destroy the data or make it otherwise unavailable, and become administrators of the database server.

| S.No | Database    | Command                                                                                            |
|------|-------------|----------------------------------------------------------------------------------------------------|
| 1.   | MySQL       | SLEEP (Time) –Delays the output execution                                                          |
| 2.   | SQLite      | RANDOMBLOB (N) –It returns a BLOB value containing N-Bytes                                         |
| 3.   | Oracle      | TO_CLOB-converts NCLOB values in a LOB column                                                      |
| 4.   | PostgresSQL | DENSE_RANK ()-Computes the rank of a row in an ordered group of rows without skipping rank values. |
| 5.   | MongoDB     | FIND()-To iterate over results fromMongoDB                                                         |
| 6.   | IBM DB2     | COALESCE -returns the first non-null expression in a list of expressions.                          |


## Prevention

<a name="inputval" />

### Input Validation

Regular expressions can be used to whitelist structured data
In case of fixed values, determine if user input matches one of the fixed value

```python
match = re.search(r"^([a-zA-Z0-9_\-\.]+)@([a-zA-Z0-9_\-\.]+)\.([a-zA-Z]{2,5})$", user_email_input)
db_input = match.span()
```
<a name="escape" />

### Escaping 

Use character escaping functions for user input. 

```python
_mysql.escape_string(query)
```

<a name="parameterize" />

### Parameterized Statements

Parameterized statements make sure that the parameters (i.e. inputs) passed into SQL statements are treated in a safe manner.

Avoid doing 

```python
sql = "INSERT INTO TABLE_A (COL_A,COL_B) VALUES (%s, %s)" % (val1, val2)
cursor.execute(sql)
```

Instead use

```python
sql = "INSERT INTO TABLE_A (COL_A,COL_B) VALUES (%s, %s)"
cursor.execute(sql, (val1, val2))
```
<a name="orm" />

### Use Object Relation Mapping Frameworks

Many development teams prefer to use Object Relational Mapping (ORM) frameworks to make the translation of SQL result sets into code objects more seamless. ORM tools often mean developers will rarely have to write SQL statements in their code – and these tools thankfully use parameterized statements under the hood.  

<a name="admin" />

### Avoid admininstrative priviliges

Dont connect application to the database using an account with root access

<a name="xss" />

## XSS (Cross Site Scripting)

Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user. Flaws that allow these attacks to succeed are quite widespread and occur anywhere a web application uses input from a user within the output it generates without validating or encoding it.

## Prevention

<a name="innerhtml" />

### Don't use innerHTML in React

Never try to add tags using innerHTML

```js
el.innerHTML = "content"
const newContent = "<script>alert('this script tage is the input from the user')</script>";
el.innerHTML = newContent
```

Never use dangerouslyInnerHTML

```js
<div  dangerouslyInnerHTML={{ __html: html }}/>
```

Never try to use InnerHTML from the module dangerously-set-html-content

```js
<InnerHTML html={this.state.html} />
```

Instead do this, avoid it we can use the normal tags like <div><span> and render the output to the dom using a java script variable

```js
state = {
    htmlCon = "<script>alert("will not be executed")</script>"
}
// so under the main component render function 
    return(
        <React.Fragment>
        <div>{thid.state.htmlCon}</div>
        </React.Fragment>
    )
```




<a name="references" />

## References

* https://www.ptsecurity.com/ww-en/analytics/knowledge-base/how-to-prevent-sql-injection-attacks/
* https://www.hacksplaining.com/prevention/sql-injection
* https://portswigger.net/web-security/sql-injection/union-attacks
* https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns
* https://portswigger.net/web-security/sql-injection/union-attacks/lab-find-column-containing-text
* https://portswigger.net/web-security/dom-based
* https://owasp.org/www-community/attacks/DOM_Based_XSS
* https://portswigger.net/web-security/cross-site-scripting/dom-based