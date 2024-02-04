UPGRADE
=======

## Upgrade FROM 0.2.1 to 0.3.0

* The `CAResolverImpl` is now final and cannot be extended anymore. 
* The `CA` model class is now final and cannot be extended anymore,
  reconstruct your own entity instead.

## Upgrade FROM 0.2.1 to 0.2.2

* Translation ids have changed to fix some mismatches.
* The `PublicKeyMismatch` violation was removed.

## Upgrade FROM 0.1.0 to 0.2.0

* The `CertificateValidator` now expects a `\Pdp\PublicSuffixList` instance 
  is passed as first argument, instead of a 
  `Rollerworks\Component\PdbSfBridge\PdpManager` instance;
