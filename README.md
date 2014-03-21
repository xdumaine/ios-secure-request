I'm writing an app that uses a client-certificate to authenticate while performing a SOAP request. Unfortunately, I'm writing this app in PhoneGap, and the iOS WebView does not support Client Certificates for AJAX requests. I found some various sources of code and examples for doing this, but it took quite a bit of work to get the final result, so I wanted to post my code and explain how I made it work. I wrote this as a PhoneGap plugin, so I can call the method from javascript, and have the result returned (via a callback function) in the normal PhoneGap plugin style, but I suppose this could be used for any client-certificate authenticated request in a native iOS app. Here's the important code:

The <code>options</code> object contains my url (<code>host</code>) and my soap request (an xml string <code>data</code>)
<pre class="brush: objc; toolbar: false;">
NSURL *serverURL = [NSURL URLWithString:[NSString stringWithFormat:@"%@", [options objectForKey:@"host"]]];
NSMutableURLRequest *connectionRequest = [NSMutableURLRequest requestWithURL:serverURL

[connectionRequest setHTTPMethod:@"POST"];
[connectionRequest setValue:@"text/xml" forHTTPHeaderField:@"Content-Type"];
[connectionRequest setHTTPBody:[[options objectForKey:@"data"] dataUsingEncoding:NSUTF8StringEncoding]];

NSURLConnection * aConnection = [[NSURLConnection alloc] initWithRequest:connectionRequest delegate:self];
</pre>
Then I have NSURLConnection Delegate Methods to receive the response. One in particular, <code>didReceiveAuthenticationChallenge</code> is where I handle the client-certificate.
<pre class="brush:objc; toolbar: false;">
- (void)connection:(NSURLConnection *)connection didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge {
    // gets a certificate from local resources
    NSString *thePath = [[NSBundle mainBundle] pathForResource:@"MyCertificate" ofType:@"pfx"];
    NSData *PKCS12Data = [[NSData alloc] initWithContentsOfFile:thePath];
    CFDataRef inPKCS12Data = (CFDataRef)PKCS12Data;
    SecIdentityRef identity;

    // extract the ideneity from the certificate
    [self extractIdentity :inPKCS12Data :&amp;identity];

    SecCertificateRef certificate = NULL;
    SecIdentityCopyCertificate (identity, &amp;certificate);

    const void *certs[] = {certificate};
    CFArrayRef certArray = CFArrayCreate(kCFAllocatorDefault, certs, 1, NULL);

    // create a credential from the certificate and ideneity, then reply to the challenge with the credential
    NSURLCredential *credential = [NSURLCredential credentialWithIdentity:identity certificates:(NSArray*)certArray persistence:NSURLCredentialPersistencePermanent];
    [challenge.sender useCredential:credential forAuthenticationChallenge:challenge];
}
</pre>

Then, We need <code>extractIdentity</code> to pull the identity out of a certificate

<pre class="brush:objc; toolbar: false; collapse: true;">
- (OSStatus)extractIdentity:(CFDataRef)inP12Data :(SecIdentityRef*)identity {
    OSStatus securityError = errSecSuccess;

    CFStringRef password = CFSTR("MyCertificatePassword");
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };

    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);

    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12Data, options, &items);

    if (securityError == 0) {
        CFDictionaryRef ident = CFArrayGetValueAtIndex(items,0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
    }

    if (options) {
        CFRelease(options);
    }

    return securityError;
}
</pre>

Blam! That was the hardest part. From there, just use your other <code>NSURLConnection</code> delegate methods to handle the connection states and events. See my secure-request.m for examples.
