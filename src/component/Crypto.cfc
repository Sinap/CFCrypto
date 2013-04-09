component
{
// An Example of a cfc using CFCrypto.
    public void function init(required string symmetricKeyPath, required string privateKeyPath)
    {
        loadPaths[1] = expandPath("../");
        javaloader = createObject("component", "javaloader.JavaLoader").init(loadPaths);
        cfcrypto = javaloader.create("CFCryptoWrapper").init(symmetricKeyPath, privateKeyPath);
    }

    public string function encrypt(required string s)
    {
        return cfcrypto.encrypt(toString(s));
    }

    public string function decrypt(required string s)
    {
        return cfcrypto.decrypt(s);
    }
}
