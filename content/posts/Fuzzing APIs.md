+++
title = "Fuzzing APIs"
date = 2023-08-22T00:40:26+01:00
draft = false
description = "Deep dive into API Fuzzing w/ Postman, Burp & Wfuzz."
+++


title = 'CKS'
date = 2024-08-23T23:17:59+01:00
draft = false
+++


## 1 - Toolkits 

- `wfuzz`
- `Burp Intruder`
- `Postman’s Collection Runner`
## 2 - Goal

We’ll cover two strategies to increase your success:

- Fuzzing wide and fuzzing deep. 
- How to fuzz for improper assets management vulnerabilities, find the accepted HTTP methods for a request, and bypass input sanitization.
## 3 - What is API Fuzzing ?

API fuzzing is the process of sending requests with various types of input to an endpoint in order to provoke an unintended result.

Here's an example of modifying a key in a JSON data on a POST request , which let the server to reveal a SQL Syntax Error.

![image](https://flowhero.github.io/assets/images/shemas/sqlattemptt.png)

Your input could include 
- Symbols, 
- Numbers,
- Emojis, 
- Decimals, 
- Hexadecimal,
- System commands, 
- SQL input ... 

For instance. If the API has not implemented validation checks to handle harmful input, you could end up with a verbose error, a unique response, or (in the worst case) some sort of internal server error indicating that your fuzz caused a denial of service, killing the app.

Modifying a key in a JSON data on Post request resulted in the server revealing an SQL Syntax Error.

## 4 - Effective Fuzzing

Lets take a look at this POST request:

```http
POST /account/balance/transfer
Host: bank.com
x-access-token: hapi_token
{
"userid": 12345,
"account": 224466,
"transfer-amount": 1337.25,
}
```

To fuzz this request, you could easily set up Burp Suite or Wfuzz to submit huge payloads as the userid, account, and transfer-amount values. However, this could set off defensive mechanisms, resulting in stronger rate limiting or your token being blocked. If the API lacks these security controls, by all means release the krakens. Otherwise, your best bet is to send a few targeted requests to only one of the values at a time

Consider the fact that the transfer-amount value likely expects a relatively small number. Bank.com isn’t anticipating an individual user to transfer an amount larger than the global GDP. It also likely expects a decimal value. Thus, you might want to evaluate what happens when:

• Sending an exceptionally large number when a small number is expected

• Sending `database queries`, `system commands`, and other code

• Sending a `String of letters`  when a number is expected

• Sending a `large String of letters`  when a small string is expected

• Sending various symbols  `!@#$%^&*();':''|,./?>`

• Sending characters from unexpected languages `(漢, さ, Ж, Ѫ, Ѭ, Ѧ, Ѩ, Ѯ)`

• Sending Emojis `😀😃😄😁😆`

These requests could easily lead to verbose errors that reveal more about the application. A value in the quadrillions could additionally cause an unhandled SQL database error to be sent back as a response.

>Thus, the success of your fuzzing will depend on where you are fuzzing and what you are fuzzing with, If these inputs do not have sufficient input handling and error handling, they can often lead to exploitation.


If you are blocked or banned while fuzzing, you might want to deploy evasion techniques discussed in my blog https://flowhero.github.io/blogsite/docs/bypassing-wafs/ or else further limit the number of fuzzing requests you send.

## 5 - Choosing Fuzzing Payloads

Different fuzzing payloads can incite various types of responses. You can use either generic fuzzing payloads or more targeted ones
### 5.1 - Generic Payloads

Are those we’ve discussed so far and contain symbols, null bytes, directory traversal strings, encoded characters, large numbers, long strings, and so on.
### 5.2 - Targeted Fuzzing Payloads

Are aimed at provoking a response from specific technologies and types of vulnerabilities.

Targeted fuzzing payload types might include **API object** or **variable names**, **cross-site scripting (XSS)** payloads, **directories**, **file extensions**, **HTTP request methods**, **JSON** or **XML data**, **SQL** commands, or OS **commands** .

---

Targeted fuzzing payloads are more useful once you know the technologies being used. If you’re sending SQL fuzzing payloads to an API that leverages only NoSQL databases, your testing won’t be as effective.

You can use the following sources for fuzzing paylaods: 

- `SecLists` Payloads https://github.com/danielmiessler/SecLists

SecLists has a whole section dedicated to fuzzing, and its big-list-of-naughty-strings.txt wordlist is excellent at causing useful responses.

- `Wfuzz` Payloads https://github.com/xmendez/wfuzz

Wfuzz has a great list that combines several targeted payloads in their injection directory, called [All_attack.txt](https://raw.githubusercontent.com/xmendez/wfuzz/1b695ee9a87d66a7d7bf6cae70d60a33fae51541/wordlist/Injections/All_attack.txt)

- `fuzzdb` Payloads https://github.com/fuzzdb-project/fuzzdb

## 6 - Anomaly Detection

When an API request payload is handled properly, you should receive some sort of HTTP response code and message indicating that your fuzzing did not work. For example, sending a request with a string of letters when numbers are expected could result in a simple response like the following:

```http
HTTP/1.1 400 Bad Request
{
"error": "number required"
}
```

From this response, you can deduce that the developers configured the API to properly handle requests like yours and prepared a tailored response.

---

When input is not handled properly and causes an error, the server will often return that error in the response. For example, if you sent input like `~'!@#$%^&*()-_+` to an endpoint that improperly handles it, you could receive an error like this:

```http
HTTP/1.1 200 OK
--snip--
SQL Error: There is an error in your SQL syntax.
````

This response immediately reveals that you’re interacting with an API request that does not handle input properly and that the backend of the application is utilizing a SQL database.

## 7 - Fuzzing Wide and Deep

This section will introduce you to two fuzzing techniques: `fuzzing wide` and `fuzzing deep`. 

### 7.1 - Fuzzing Wide

**Fuzzing wide** is the act of sending an input across all of an API’s unique requests in an attempt to discover a vulnerability.

Is best used to test for issues across all unique requests. Typically, you can fuzz wide to test for improper assets management (more on this later in this blog), finding all valid request methods, token-handling issues, and other information disclosure vulnerabilities.

---
### 7.2 - Fuzzing Deep

**Fuzzing deep** is the act of thoroughly testing an individual request with a variety of inputs, replacing headers, parameters, query strings, endpoint paths, and the body of the request with your payloads.

Is best used for testing many aspects of individual requests. Most other vulnerability discovery will be done by fuzzing deep. In later chapters, we will use the fuzzing deep technique to discover different types of vulnerabilities, including BOLA, BFLA, injection, and mass assignment.

---

### 7.3 - Fuzzing Wide w/ *Postman*

I recommend using Postman to fuzz wide for vulnerabilities across an API, as the tool’s Collection Runner makes it easy to run tests against all API requests. If an API includes 150 unique requests across all the endpoints, you can set a variable to a fuzzing payload entry and test it across all 150 requests. This is particularly easy to do when you’ve built a collection or imported API requests into Postman. For example, you might use this strategy to test whether any of the requests fail to handle various “bad” characters. Send a single payload across the API and check for anomalies.

Create a Postman environment in which to save a set of fuzzing variables. This lets you seamlessly use the environmental variables from one collection to the next. Once the fuzzing variables are set as shown below, you can save or update the environment.

![image](https://flowhero.github.io/assets/images/shemas/2023_08_22_222354.png)

At the top right, select the fuzzing environment and then use the variable shortcut {{variable name}} wherever you would like to test a value in a given collection. We can for example replace x-access-token header with the first fuzzing variable. 

![image](https://flowhero.github.io/assets/images/shemas/2023_08_22_225101.png)
then start the Postman Collection Runner:

![image](https://flowhero.github.io/assets/images/shemas/2023_08_22_230418.png)

You can also look manually in the collection for some parameters or headers that you want to replace with a fuzzing variable, using **Find and Replace** feature, found at the bottom left of Postman. 

Find and Replace lets you search a collection (or all collections) and replace certain terms with a Fuzzing 209 replacement of your choice. If you were attacking the Pixi API, for example, you might notice that many placeholder parameters use tags like *email*, *number*, *string*, and *boolean*. This makes it easy to search for these values and replace them with either legitimate ones or one of your fuzzing variables, like `{{fuzz1}}`.

![image](https://flowhero.github.io/assets/images/shemas/2023_08_22_231122.png)

Next, try creating a simple test in the Tests panel to help you detect anomalies.  

```java
let response = JSON.parse(responseBody);

pm.test(“Request passes with success”, _function_() {
if (response.info!=”Success”){

pm.expect.fail(“Test fails with the following special character: “+ pm.request.body.formdata.get(“searchQ”)+ “ “ + “Errorcode:” + “ “ + response.error);  

}  
});
```

Then start the Postman Collection Runner.

![image](https://flowhero.github.io/assets/images/shemas/2023_08_22_231634.png)
### 7.4 - Fuzzing Deep w/ *Postman*

In the Wide Fuzzing, we were using 1 fuzzing variable everywhere (in this case we were testing `fuzz1 = ~'!@#$%^&*()-_+` everywhere we find `limit` parameter)
#### Scenario 1 : Fuzzing endpoints in URLs

This time, we'll be Fuzzing with the [Big List of Naughty Strings](https://gist.githubusercontent.com/DannyDainton/b820904694a91e20de1ad900cdeb3a94/raw/9f6dcabfe34506e81ca75ffb092550f709dad043/naughtyStrings.json) wordlist, we replace the parameters that we want to fuzz with `{{naughtyValue}}` that will remain undefined:

![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_013105.png)

until we pass through the data from an external file as shown in the second figure below:

|  |  |
| ------------------------------------------ | ------------------------------------------ |
|                      ![image](https://flowhero.github.io/assets/images/shemas/2023_08_22_230256.png)                      |        ![image](https://flowhero.github.io/assets/images/shemas/2023_08_22_232306.png)                                    |


Then we select only the endpoints we want test since we are performing deep fuzzing:

![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_014009.png)

we have **504** iterations because we have **504** naughtyValue. After running the test we can see the results live,

![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_014928.png)

Then we can check if there is any abnormal response by looking at Code Status and Size of the Response, we could set up more than just one variable to test, we could actually choose an endpoint with multiple parameters and assign them all as `{{naughtyValue}}`  variables, then start fuzzing, but this is something that we can do using `Burp Intuder` & `Wfuzz` (and that's what we'll do in the next section), Postman collection runner will help us fuzz for an entire collection (or just parts of it) , which is something that is not available in `Burp` & `Wfuzz`

#### Scenario 2: Fuzzing Parameters in POST Requests

We could also fuzz for parameters inside POST Requests, go to the request that you want to test, modify the parameters inside:

![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_210000.png)

Start the Collection Runner and choose the endpoints where you modified the parameters to `{{naughtyValue}}` and run the Collection Runner: 


![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_210114.png)

You can now see that the parameters that we specified are now different in each iteration:

Iteration 142:
![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_211713.png)

Iteration 134:
![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_211725.png)



Keep in mind that this is a `Battering Ram Attack Mode`, you can take a look at the [4 Attacks Types Here](https://portswigger.net/burp/documentation/desktop/tools/intruder/configure-attack/attack-types)

For `Pitchforck` :

|                                            |                                      |
| ------------------------------------------ | ------------------------------------ |
| This is How we set the payload file        | Preview in Postman Collection Runner |
| ![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_222423.png) | ![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_222612.png)                                     |

Now in each iteration, each of the parameters will have its value from the payload file.

>The total number of requests generated in the attack is the number of payloads in the smallest payload set.

For `Cluster Bomb` :

|                                            |                                      |
| ------------------------------------------ | ------------------------------------ |
| This is How we set the payload file        | Preview in Postman Collection Runner |
| ![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_224247.png) | ![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_224435.png)                                     |

>The total number of requests generated in the attack is the product of the number of payloads in all defined payload sets - this may be extremely large.


We could've used of course different payload list for each parameter (for example `naughtyValue1` for *ewallet* and `naughtyValue2` for *contact*, but we need to append the two lists , this is similar to Sniper Attack in Burp Intruder, the Difference is that we can run this across all API endpoints , while in burp we have to run the attack for each endpoint manually.
### 7.5 - Fuzzing Deep w/ *Burpsuite*

Fuzzing with Burp is very common so I guess you can skip this section, we are not going to dive deep here anyway.

To send the request to Burp, just set up the proxy in Postman and Burp:

![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_211050.png)

Send the request from Postman and you'll see the request in Burp HTTP History:

![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_221016.png)

You can now send it to the intruder, set parameters to fuzz, and payload sets and attacks type then start the attack ... 

![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_221114.png)

### 7.6 - Fuzzing Deep w/ *Wfuzz*

One advantage of `Wfuzz` is that it’s considerably faster than Burp Suite, so we can increase our payload size.

This is an example on how to perform Battering ram Attack, specifying the access_token for authentication and the body data. we filtered `400` Code Status, the `-p 127.0.0.1:8080` is for proxying your request to Burp, which is optional of course, you can use it to see if the requests that are by `Wfuzz` are malformed so that you can fix something in your one-liner:

```shell
wfuzz -z file,/home/kali/big-list-of-naughty-strings.txt -H "Content-Type: application/json" -H "x-access-token: [...]" --hc 400 -X PUT -d "{
	\"user\": \"FUZZ\",
	\"pass\": \"FUZZ\",
	\"id\": \"FUZZ\",
	\"name\": \"FUZZ\",
	\"is_admin\": \"FUZZ\",
	\"account_balance\": \"FUZZ\"
}" -u [TARGET_URL]
```

### 7.7 - Fuzzing Wide for Improper Assets Management

Improper assets management vulnerabilities arise when an organization exposes APIs that are either retired, in a test environment, or still in development. In any of these cases, there is a good chance the API has fewer protections than its supported production counterparts. Improper assets management might affect only a single endpoint or request, so it’s often useful to fuzz wide to test if improper assets management exists for any request across an API.

>In order to fuzz wide for this problem, it helps to have a specification of the API or a
collection file that will make the requests available in Postman. This section assumes
you have an API collection available

You can find improper assets management vulnerabilities by paying close attention to outdated API documentation. If the production version of the sample API is **v2**, so it would be a good idea to test a few keywords, like **v1**, **v3**, **test**, **mobile**, **uat**, **dev**, and **old**, as well as any interesting paths discovered during analysis or reconnaissance testing. Additionally, some API providers will allow access to administrative functionality by adding /internal/ to the path before or after the versioning, which would look like this: `/api/v2/internal/users` `/api/internal/v2/users`

You can use Postman Collection Runner, use "Find and Replace" to replace  `v3` across all the collection by `v1` , run the collection and look for anomalies, you can repeat the same for `dev`, `test` ... (This is Wide Fuzzing)

To make our testing easier, we’ll set up the same test for status codes of 200 we used earlier in this chapter. If the API provider typically responds with status code 404 for non existent resources, a 200 response for those resources would likely indicate that the API is vulnerable.

. If you discover an improper asset management vulnerability,
your next step will be to test the non-production endpoint for additional
weaknesses.


## 8 - Testing Request Methods with Wfuzz

You can fuzz an endpoint's supported HTTP Methods:

```sh
wfuzz -z list,GET-HEAD-POST-PUT-PATCH-TRACE-OPTIONS-CONNECT- -X FUZZ http://target.com/api/v2/account

********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer *
********************************************************
Target: http://testsite.com/api/v2/account
Total requests: 8

==========================================================
ID Response Lines Word Chars Payload
==========================================================
000000008: 405 7 L 11 W 163 Ch "CONNECT"
000000004: 405 7 L 11 W 163 Ch "PUT"
000000005: 405 7 L 11 W 163 Ch "PATCH"
000000007: 405 7 L 11 W 163 Ch "OPTIONS"
000000006: 405 7 L 11 W 163 Ch "TRACE"
000000002: 200 0 L 0 W 0 Ch "HEAD"
000000001: 200 0 L 107 W 2610 Ch "GET"
000000003: 405 0 L 84 W 1503 Ch "POST"
```

You can now see valid Methods (those with Status Code `200` and Methods Not Allowed ones `405` )

## 9 - Fuzzing “Deeper” to Bypass Input Sanitization

In case you are fuzzing a sanitized parameter, let's say that the email field only accept emails formats ( for example `user@gmail.com` ) in this case you can append a string terminator (`%00` in this case) to the email, followed by the variable that will be fuzzed:

```json
"email": "a@b.com%00§test§"
```

Better yet, there are enough possible symbols to send that you could add a second payload position for typical escape characters, like this: 

```json
"user": "a@b.com§escape§§test§"
```

String terminators you can use
```
%00
0x00
//
;
%
!
?
[]
%5B%5D
%09
%0a
%0b
%0c
%0e
```

Use a set of potential escape symbols for the §escape§ payload and the payload you want to execute as the §test§. To perform this test, use Burp Suite’s cluster bomb attack.

![image](https://flowhero.github.io/assets/images/shemas/2023_08_23_234218.png)


## 10 - Summary 

This blog covered the art of fuzzing APIs, one of the most important attack techniques you’ll need to master. By sending the right inputs to the right parts of an API request, you can discover a variety of API weaknesses. We covered two strategies, fuzzing wide and deep, useful for testing the entire attack surface of large APIs.

