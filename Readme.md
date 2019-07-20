# JWT C# library

A C# class that can sign and validate JWT tokens, wrapped in a simple library with a couple of helper functions.

## RSA Algorithm

To generate a compatible private key
```
openssl genrsa -out private.key 4096
```

To generate a compatible public key
```
openssl rsa -in private.key -outform PEM -pubout -out public.pem
```

### Sign a JWT token
```cs
using Newtonsoft.Json;

JwtManager.RsJwt jwt = new JwtManager.RsJwt
{
    KeySize = JwtManager.Helpers.KeySize.S256, // This can be also 384 or 512
    PrivateKey = PrivateKey
};

string strToken = JsonConvert.SerializeObject(myToken);
string signedToken = jwt.Sign(strToken);
```
In case of an error, an Exception will be thrown.

### Validate a JWT token
```cs
using Newtonsoft.Json;

JwtManager.RsJwt jwt = new JwtManager.RsJwt
{
    KeySize = JwtManager.Helpers.KeySize.S256, // This can be also S384 or S512
    PublicKey = PublicKey
};

string payload = jwt.Validate(strToken);
var myToken = JsonConvert.DeserializeObject<JwtToken>(payload);
```

In case of an error, an Exception will be thrown.


## HMAC Algorithm

For this you need a secret in a string variable. Longer secret is better

### Sign a JWT token
```cs
using Newtonsoft.Json;

string secret = "setyourverysecretkeyhere";

JwtManager.HsJwt jwt = new JwtManager.HsJwt
{
    KeySize = JwtManager.Helpers.KeySize.S256, // This can be also 384 or 512
    Secret = secret
};

string strToken = JsonConvert.SerializeObject(myToken);
string signedToken = jwt.Sign(strToken);
```
In case of an error, an Exception will be thrown.

### Validate a JWT token
```cs
using Newtonsoft.Json;

string secret = "setyourverysecretkeyhere";

JwtManager.HsJwt jwt = new JwtManager.HsJwt
{
    KeySize = JwtManager.Helpers.KeySize.S256, // This can be also S384 or S512
    Secret = secret
};

string payload = jwt.Validate(strToken);
var myToken = JsonConvert.DeserializeObject<JwtToken>(payload);
```

In case of an error, an Exception will be thrown.

## Other Info

The code has been tested both as a .NET and .NET Core library.

Check the **JwtManagerTests** project for more examples on how to use
