# pem-utils
A small Java library for reading PEM-encoded DER files of various types.

# Building

    $ mvn package

# Usage

## Quick and Simple

    import net.christopherschultz.pemutils.PEMFile;
    .
    .
    .
    Collection<PEMFile.Entry> entries = PEMFile.decode(_string or stream_);
    for(PEMFile.Entry entry : entries) {
        if(entry instanceof PEMFile.CertificateEntry) {
            System.out.println("This is a certificate: " + ((PEMFile.CertificateEntry)entry).getCertificate());
        } else if(entry instanceof PEMFile.PrivateKeyEntry) {
            System.out.println("This is a private key of type " + ((PEMFile.PrivateKeyEntry)entry).getAlgorithm());
        }
    }

## Somewhat more involved...


    import net.christopherschultz.pemutils.PEMFile;
    .
    .
    .
    PEMFile pm = new PEMFile(_string or stream_);
    PEMFile.Entry entry;
    while(null != (entry = pm.getNext())) {
      // Do whatever with the entry
    }

