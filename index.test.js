import OpenSSL from '@superhero/openssl'
import assert  from 'node:assert'
import { suite, test }      from 'node:test'
import { X509Certificate }  from 'node:crypto'

suite('@superhero/openssl', () =>
{
  test('Create a Hybrid Self-Signed Certificate (CA)', async () => 
  {
    const
      openssl     = new OpenSSL(),
      certificate = await openssl.hybrid(),
      verified    = await openssl.verify(certificate),
      x509        = new X509Certificate(certificate.cert)
  
    assert.ok(verified)
    assert.ok(certificate.key)
    assert.ok(certificate.cert)
    assert.ok(certificate.text)
    assert.ok(certificate.meta)
    assert.ok(x509.ca)
    assert.ok(x509.checkIssued(x509))
  })

  test('Create Root Anchor Certificate Authority (CA)', async () => 
  {
    const
      openssl   = new OpenSSL(),
      rootCA    = await openssl.root(),
      verified  = await openssl.verify(rootCA)
  
    assert.ok(verified)
    assert.ok(rootCA.key)
    assert.ok(rootCA.cert)
    assert.ok(rootCA.text)
    assert.ok(rootCA.meta)
    assert.ok(new X509Certificate(rootCA.cert).ca)
  })

  test('Create Intermediate Certificate Authority (CA) from a Root CA', async () => 
  {
    const 
      openssl         = new OpenSSL(),
      rootCA          = await openssl.root(),
      intermediateCA  = await openssl.intermediate(rootCA),
      verified        = await openssl.verify(intermediateCA, rootCA)
  
    assert.ok(verified)
    assert.ok(intermediateCA.key)
    assert.ok(intermediateCA.cert)
    assert.ok(intermediateCA.text)
    assert.ok(intermediateCA.meta)
    assert.ok(new X509Certificate(intermediateCA.cert).ca)
  })
  
  test('Create End-Entity Certificate (leaf) from a Root CA', async () => 
  {
    const
      openssl   = new OpenSSL(),
      rootCA    = await openssl.root(),
      leaf      = await openssl.leaf(rootCA),
      verified  = await openssl.verify(leaf, rootCA)
  
    assert.ok(verified)
    assert.ok(leaf.key)
    assert.ok(leaf.cert)
    assert.ok(leaf.text)
    assert.ok(leaf.meta)
    assert.ok(false === new X509Certificate(leaf.cert).ca)
  })
  
  test('Create End-Entity Certificate (leaf) from an Intermediate CA', async () => 
  {
    const
      openssl   = new OpenSSL(),
      rootCA    = await openssl.root(),
      ICA       = await openssl.intermediate(rootCA),
      leaf      = await openssl.leaf(ICA),
      verified  = await openssl.verify(leaf, rootCA, ICA)
  
    assert.ok(verified)
    assert.ok(leaf.key)
    assert.ok(leaf.cert)

    const 
      x509Root = new X509Certificate(rootCA.cert),
      x509ICA  = new X509Certificate(ICA.cert),
      x509Leaf = new X509Certificate(leaf.cert)

    assert.ok(x509Root.ca)
    assert.ok(x509ICA.ca)
    assert.ok(false === x509Leaf.ca)
    assert.ok(false === x509Leaf.checkIssued(x509Root))
    assert.ok(false === x509Root.checkIssued(x509ICA))
    assert.ok(x509ICA.checkIssued(x509Root))
    assert.ok(x509Leaf.checkIssued(x509ICA))
  })
  
  test('Create Server End-Entity Certificate (leaf)', async () => 
  {
    const
      openssl         = new OpenSSL(),
      rootCA          = await openssl.root(),
      intermediateCA  = await openssl.intermediate(rootCA),
      serverCert      = await openssl.serverCert(intermediateCA),
      serverVerified  = await openssl.verify(serverCert, rootCA, intermediateCA)
  
    assert.ok(serverVerified)
    assert.ok(serverCert.key)
    assert.ok(serverCert.cert)
    assert.ok(false === new X509Certificate(serverCert.cert).ca)
  })
  
  test('Create Client End-Entity Certificate (leaf)', async () => 
  {
    const
      openssl         = new OpenSSL(),
      rootCA          = await openssl.root(),
      intermediateCA  = await openssl.intermediate(rootCA),
      clientCert      = await openssl.clientCert(intermediateCA),
      clientVerified  = await openssl.verify(clientCert, rootCA, intermediateCA)
  
    assert.ok(clientVerified)
    assert.ok(clientCert.key)
    assert.ok(clientCert.cert)
    assert.ok(false === new X509Certificate(clientCert.cert).ca)
  })

  test('Password Protected Private Key', async () => 
  {
    const
      config          = { password : 'ABC def 0123 \\ \'"` !@#$%^&*()_+[]{}|;:,.<>?~-=' },
      openssl         = new OpenSSL(),
      hybridCA        = await openssl.hybrid(config),
      rootCA          = await openssl.root(config),
      intermediateCA  = await openssl.intermediate(rootCA, config),
      leaf            = await openssl.leaf(intermediateCA, config),
      verified        = await openssl.verify(leaf, rootCA, intermediateCA)
  
    assert.ok(verified)

    assert.ok(hybridCA.key)
    assert.ok(hybridCA.key.includes('ENCRYPTED'))

    assert.ok(rootCA.key)
    assert.ok(rootCA.key.includes('ENCRYPTED'))

    assert.ok(intermediateCA.key)
    assert.ok(intermediateCA.key.includes('ENCRYPTED'))

    assert.ok(leaf.key)
    assert.ok(leaf.key.includes('ENCRYPTED'))
  })
  
  test('Password Protected Private Key (different input and output)', async () => 
  {
    const
      rootPass          = 'root password',
      intermediatePass  = 'intermediate password',
      leafPass          = 'leaf password',
      openssl           = new OpenSSL(),
      hybridCA          = await openssl.hybrid({ password : { output:rootPass } }),
      rootCA            = await openssl.root({ password : { output:rootPass } }),
      intermediateCA    = await openssl.intermediate(rootCA, { password : { input:rootPass, output:intermediatePass } }),
      leaf              = await openssl.leaf(intermediateCA, { password : { input:intermediatePass, output:leafPass } }),
      verified          = await openssl.verify(leaf, rootCA, intermediateCA)
  
    assert.ok(verified)

    assert.ok(hybridCA.key)
    assert.ok(hybridCA.key.includes('ENCRYPTED'))

    assert.ok(rootCA.key)
    assert.ok(rootCA.key.includes('ENCRYPTED'))

    assert.ok(intermediateCA.key)
    assert.ok(intermediateCA.key.includes('ENCRYPTED'))

    assert.ok(leaf.key)
    assert.ok(leaf.key.includes('ENCRYPTED'))
  })
  
  test('DNS Restricted Certificate', async () => 
  {
    const
      host           = 'example.com',
      openssl        = new OpenSSL(),
      hybrid         = await openssl.hybrid({ dns: [host] }),
      rootCA         = await openssl.root(),
      intermediateCA = await openssl.intermediate(rootCA, { dns: [host] }),
      leaf           = await openssl.leaf(intermediateCA, { dns: [host] }),
      verified       = await openssl.verify(leaf, rootCA, intermediateCA)
  
    assert.ok(verified)
    assert.ok(new X509Certificate(hybrid.cert).checkHost(host))
    assert.ok(new X509Certificate(leaf.cert).checkHost(host))
  })
  
  test('IP Restricted Certificate', async () => 
  {
    const
      ip             = '127.0.0.1',
      openssl        = new OpenSSL(),
      hybrid         = await openssl.hybrid({ ip: [ip] }),
      rootCA         = await openssl.root(),
      intermediateCA = await openssl.intermediate(rootCA, { ip: [ip] }),
      leaf           = await openssl.leaf(intermediateCA, { ip: [ip] }),
      verified       = await openssl.verify(leaf, rootCA, intermediateCA)
  
    assert.ok(verified)
    assert.ok(new X509Certificate(hybrid.cert).checkIP(ip))
    assert.ok(new X509Certificate(leaf.cert).checkIP(ip))
  })

  suite('Different Algorithm and Hash Combinations', () =>
  {
    for(const algorithm of Object.values(OpenSSL.ALGO))
    {
      for(const hash of Object.values(OpenSSL.HASH))
      {
        test(`${algorithm} ${hash.toUpperCase()}`, async (ctx) => 
        {
          const
            openssl        = new OpenSSL(),
            hybrid         = await openssl.hybrid({ algorithm, hash }),
            rootCA         = await openssl.root({ algorithm, hash }),
            intermediateCA = await openssl.intermediate(rootCA, { algorithm, hash }),
            leaf           = await openssl.leaf(intermediateCA, { algorithm, hash })

          for(const certificate of [hybrid, rootCA, intermediateCA, leaf])
          {
            assert.ok(certificate.key)
            assert.ok(certificate.cert)
            assert.ok(certificate.text)
            assert.ok(certificate.meta)
          }

          switch(`${algorithm}-${hash}`)
          {
            case `${OpenSSL.ALGO.RSA2048}-${OpenSSL.HASH.SHA1}`:
            case `${OpenSSL.ALGO.RSA4096}-${OpenSSL.HASH.SHA1}`:
            case `${OpenSSL.ALGO.ECDSAP256}-${OpenSSL.HASH.SHA1}`:
            case `${OpenSSL.ALGO.ECDSAP384}-${OpenSSL.HASH.SHA1}`:
            case `${OpenSSL.ALGO.ECDSAP521}-${OpenSSL.HASH.SHA1}`:
            {
              assert.ok(await openssl.verify.basic(hybrid))
              assert.ok(await openssl.verify.basic(rootCA))
              assert.ok(await openssl.verify.basic(intermediateCA, rootCA))
              assert.ok(await openssl.verify.basic(leaf, rootCA, intermediateCA))
              ctx.diagnostic('VERIFY LVL:0:BASIC')
              return
            }
            case `${OpenSSL.ALGO.ECDSAP256}-${OpenSSL.HASH.SHA224}`:
            case `${OpenSSL.ALGO.ECDSAP384}-${OpenSSL.HASH.SHA224}`:
            {
              assert.ok(await openssl.verify.weak(hybrid))
              assert.ok(await openssl.verify.weak(rootCA))
              assert.ok(await openssl.verify.weak(intermediateCA, rootCA))
              assert.ok(await openssl.verify.weak(leaf, rootCA, intermediateCA))
              ctx.diagnostic('VERIFY LVL:1:WEAK')
              return
            }
            case `${OpenSSL.ALGO.RSA2048}-${OpenSSL.HASH.SHA224}`:
            case `${OpenSSL.ALGO.RSA2048}-${OpenSSL.HASH.SHA256}`:
            case `${OpenSSL.ALGO.RSA2048}-${OpenSSL.HASH.SHA384}`:
            case `${OpenSSL.ALGO.RSA2048}-${OpenSSL.HASH.SHA512}`:
            case `${OpenSSL.ALGO.RSA4096}-${OpenSSL.HASH.SHA224}`:
            case `${OpenSSL.ALGO.ECDSAP384}-${OpenSSL.HASH.SHA224}`:
            case `${OpenSSL.ALGO.ECDSAP521}-${OpenSSL.HASH.SHA224}`:
            {
              assert.ok(await openssl.verify.average(hybrid))
              assert.ok(await openssl.verify.average(rootCA))
              assert.ok(await openssl.verify.average(intermediateCA, rootCA))
              assert.ok(await openssl.verify.average(leaf, rootCA, intermediateCA))
              ctx.diagnostic('VERIFY LVL:2:AVERAGE')
              return
            }
            case `${OpenSSL.ALGO.RSA4096}-${OpenSSL.HASH.SHA256}`:
            case `${OpenSSL.ALGO.RSA4096}-${OpenSSL.HASH.SHA384}`:
            case `${OpenSSL.ALGO.RSA4096}-${OpenSSL.HASH.SHA512}`:
            case `${OpenSSL.ALGO.ECDSAP256}-${OpenSSL.HASH.SHA256}`:
            case `${OpenSSL.ALGO.ECDSAP256}-${OpenSSL.HASH.SHA384}`:
            case `${OpenSSL.ALGO.ECDSAP256}-${OpenSSL.HASH.SHA512}`:
            case `${OpenSSL.ALGO.ECDSAP384}-${OpenSSL.HASH.SHA256}`:
            case `${OpenSSL.ALGO.ECDSAP521}-${OpenSSL.HASH.SHA256}`:
            case `${OpenSSL.ALGO.EdDSAEd25519}-${OpenSSL.HASH.SHA1}`:
            case `${OpenSSL.ALGO.EdDSAEd25519}-${OpenSSL.HASH.SHA224}`:
            case `${OpenSSL.ALGO.EdDSAEd25519}-${OpenSSL.HASH.SHA256}`:
            case `${OpenSSL.ALGO.EdDSAEd25519}-${OpenSSL.HASH.SHA384}`:
            case `${OpenSSL.ALGO.EdDSAEd25519}-${OpenSSL.HASH.SHA512}`:
            {
              assert.ok(await openssl.verify(hybrid))
              assert.ok(await openssl.verify(rootCA))
              assert.ok(await openssl.verify(intermediateCA, rootCA))
              assert.ok(await openssl.verify(leaf, rootCA, intermediateCA))
              ctx.diagnostic('VERIFY LVL:3:STANDARD')
              return
            }
            case `${OpenSSL.ALGO.ECDSAP384}-${OpenSSL.HASH.SHA384}`:
            case `${OpenSSL.ALGO.ECDSAP384}-${OpenSSL.HASH.SHA512}`:
            case `${OpenSSL.ALGO.ECDSAP521}-${OpenSSL.HASH.SHA384}`:
            case `${OpenSSL.ALGO.EdDSAEd448}-${OpenSSL.HASH.SHA1}`:
            case `${OpenSSL.ALGO.EdDSAEd448}-${OpenSSL.HASH.SHA224}`:
            case `${OpenSSL.ALGO.EdDSAEd448}-${OpenSSL.HASH.SHA256}`:
            case `${OpenSSL.ALGO.EdDSAEd448}-${OpenSSL.HASH.SHA384}`:
            case `${OpenSSL.ALGO.EdDSAEd448}-${OpenSSL.HASH.SHA512}`:
            {
              assert.ok(await openssl.verify.strong(hybrid))
              assert.ok(await openssl.verify.strong(rootCA))
              assert.ok(await openssl.verify.strong(intermediateCA, rootCA))
              assert.ok(await openssl.verify.strong(leaf, rootCA, intermediateCA))
              ctx.diagnostic('VERIFY LVL:4:STRONG')
              return
            }
            case `${OpenSSL.ALGO.ECDSAP521}-${OpenSSL.HASH.SHA512}`:
            default:
            {
              assert.ok(await openssl.verify.robust(hybrid))
              assert.ok(await openssl.verify.robust(rootCA))
              assert.ok(await openssl.verify.robust(intermediateCA, rootCA))
              assert.ok(await openssl.verify.robust(leaf, rootCA, intermediateCA))
              ctx.diagnostic('VERIFY LVL:5:ROBUST')
              return
            }
          }
        })
      }
    }
  })
})