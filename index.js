import { exec }      from 'node:child_process'
import { promisify } from 'node:util'

const asyncExec = promisify(exec)

/**
 * @memberof @superhero/tls/openssl:OpenSSL
 * @typedef {Object} Config
 * @property {string} [algorithm]   - The algorithm to use. @example: EdDSA:Ed25519
 * @property {string} [hash]        - The hash algorithm to use. @example: sha256
 * @property {number} [days]        - The number of days the certificate is valid for.
 * @property {Object} [subject]     - The subject of the certificate. Many of these attributes are non-essential and/or non-standard.
 * @property {string} [subject.BC]  - Business Category attribute to classify the business type (e.g., Government, Non-Profit, or Corporation). @example: BC=Private Organization
 * @property {string} [subject.C]   - A two-letter country code based on the ISO 3166-1 standard (e.g., ES, US or UK). @example: C=ES
 * @property {string} [subject.CN]  - The Common Name is usually the most important attribute. It often represents the fully qualified domain name (FQDN) of the server (for SSL/TLS certificates) or the individual/entity's name (for personal certificates) @example: CN=example.com
 * @property {string} [subject.CP]  - Certificate Policies attribute is used to define the policies under which the certificate was issued. @example: CP=1a2b3c
 * @property {string} [subject.DC]  - Domain Component attribute is used to build the distinguished name (DN) of the certificate. It is used to identify the domain name of the entity. @example: DC=example, DC=com
 * @property {string} [subject.E]   - Email Address attribute contains the email address of the entity (usually a person or a service).
 * @property {string} [subject.GN]  - Given Name attribute specifies the first name or given name of an individual. @example: GN=John
 * @property {string} [subject.GQ]  - Generation Qualifier attribute is used to specify the generation qualifier of an individual. @example: GQ=Jr
 * @property {string} [subject.L]   - City or locality in which the entity is located. Can't be abbreviated. @example: L=Barcelona
 * @property {string} [subject.O]   - Organization attribute specifies the legal name of the organization or company. @example: O=Company Name Example S.L.
 * @property {string} [subject.OU]  - Organizational Unit, which is typically the name of the department or organization unit making the request. @example: OU=IT
 * @property {string} [subject.POB] - Post Office Box attribute is used to specify the post office box number of the entity. @example: POB=PO Box 123456
 * @property {string} [subject.ST]  - State or province where the entity is located. Can't be abbreviated. @example: ST=Catalonia
 * @property {string} [subject.SN]  - Serial Number attribute is used to uniquely identify the certificate within the CA's systems. Surname or last name of an individual subject. @example: SN=123456
 * @property {string} [subject.SN]  - Surname or last name of an individual subject. @example: SN=Smith
 * @property {string} [subject.T]   - Title attribute specifies the job title, position, or profession of an individual - such as "Dr." or "Mr." for individuals. @example: T=Mrs
 * @property {string} [subject.UID] - UID attribute is used as a unique identifier for the entity (such as a user or device). @example: UID=123456
 * @property {number} [timeout]     - Timeout in milliseconds for the command to finalize.
 * @property {string[]} [dns]       - The domain names to include in the certificate.
 * @property {string[]} [ip]        - The IP addresses to include in the certificate.
 * @property {string[]} [flags]     - Additional flags to pass to the openssl command.
 * @property {string|Object} [password] - The password to the input private key, and use the same to encrypt the output private key with.
 * @property {string} [password.output] - The password to encrypt the output private key with.
 * @property {string} [password.input]  - The password of the input private key.
 * @property {Object} [extension]                        - Add a specific extension to the certificate or certificate request.
 * @property {string} [extension.basicConstraints]       - Specifies whether the certificate is a CA certificate or an end-entity certificate.
 * @property {string} [extension.keyUsage]               - Specifies the intended purpose of the public key contained in the certificate.
 * @property {string} [extension.subjectKeyIdentifier]   - The hash of the public key.
 * @property {string} [extension.authorityKeyIdentifier] - The keyid linking to the root CA's subjectKeyIdentifier.
 * @property {string} [extension.subjectAltName]         - Standard way to specify domain names in certificates (subject:CN is deprecated).
 * @property {string} [extension.extendedKeyUsage]       - Defines specific purposes for which the certificate can be used.
 * @property {string} [extension.nameConstraints]        - Which hosts are permitted to be signed by the certificate.
 */

/**
 * @memberof @superhero/tls/openssl:OpenSSL
 * @typedef {Object} Certificate
 * @property {string} key  - The private key.
 * @property {string} cert - The certificate.
 * @property {string} text - The certificate in text format.
 * @property {string} meta - The meta information from the openssl command.
 */

/**
 * Generate certificates using openssl.
 * @see https://www.openssl.org/docs/man1.1.1/man1/req.html
 */
export default class OpenSSL
{
  static ALGO =
  {
    RSA2048      : 'RSA:2048',
    RSA4096      : 'RSA:4096',
    ECDSAP256    : 'ECDSA:P-256',
    ECDSAP384    : 'ECDSA:P-384',
    ECDSAP521    : 'ECDSA:P-521',
    EdDSAEd25519 : 'EdDSA:Ed25519',
    EdDSAEd448   : 'EdDSA:Ed448',
  }

  static HASH =
  {
    SHA1   : 'sha1',
    SHA224 : 'sha224',
    SHA256 : 'sha256',
    SHA384 : 'sha384',
    SHA512 : 'sha512',
  }

  /**
   * Create a self-signed hybrid certificate.
   * @param {Config} config
   * @returns {Certificate}
   * @throws {Error} E_TLS_OPENSSL_HYBRID
   */
  async hybrid(config)
  {
    try
    {
      config = Object.assign(
      {
        subject : { CN:'Self-Signed Hybrid Certificate (CA)' },
        days    : 365,
        extensions:
        {
          basicConstraints        : 'critical,CA:TRUE,pathlen:1',
          keyUsage                : 'critical,digitalSignature,keyEncipherment,keyCertSign,cRLSign',
          subjectKeyIdentifier    : 'hash',
          authorityKeyIdentifier  : 'keyid:always,issuer:always',
          extendedKeyUsage        : 'serverAuth,clientAuth'
        }
      }, config)
      
      const { dns, ip, extensions: { subjectAltName, nameConstraints } } = config

      config.extensions.nameConstraints = nameConstraints || this.#conformNameConstraints(dns, ip)
      config.extensions.subjectAltName  = subjectAltName  || this.#conformSan(dns, ip)

      const
        sslOptions  = this.#conformSslOptions(config),
        sslArgs     = '-x509 -out /dev/stdout -keyout /dev/stdout -text -batch -multivalue-rdn',
        result      = await this.#exec(`openssl req ${sslArgs} -days ${config.days} ${sslOptions}`, config.timeout)

      return this.#conformPemCert(result)
    }
    catch(reason)
    {
      const error = new Error(`Failed to create self-signed hybrid certificate`)
      error.code  = 'E_TLS_OPENSSL_HYBRID'
      error.cause = reason
      throw error
    }
  }
  
  /**
   * Create a root authority certificate.
   * @param {Config} config
   * @returns {Certificate}
   * @throws {Error} E_TLS_OPENSSL_ROOT
   */
  async root(config)
  {
    try
    {
      config = Object.assign(
      {
        subject : { CN:'Root Authority Certificate (CA)' },
        days    : 365 * 10,
        extensions:
        {
          basicConstraints        : 'critical,CA:TRUE,pathlen:1',
          keyUsage                : 'critical,keyCertSign,cRLSign',
          subjectKeyIdentifier    : 'hash',
          authorityKeyIdentifier  : 'keyid:always'
        }
      }, config)

      const
        sslOptions  = this.#conformSslOptions(config),
        sslArgs     = '-x509 -out /dev/stdout -keyout /dev/stdout -text -batch -multivalue-rdn',
        result      = await this.#exec(`openssl req ${sslArgs} -days ${config.days} ${sslOptions}`, config.timeout)

      return this.#conformPemCert(result)
    }
    catch(reason)
    {
      const error = new Error(`Failed to create root authority certificate (CA)`)
      error.code  = 'E_TLS_OPENSSL_ROOT'
      error.cause = reason
      throw error
    }
  }

  /**
   * Create an intermediate certificate authority.
   * @param {Certificate} ca
   * @param {Config} config
   * @returns {Certificate}
   * @throws {Error} E_TLS_OPENSSL_INTERMEDIATE
   */
  async intermediate(ca, config)
  {
    try
    {
      config = Object.assign(
      {
        subject : { CN:'Intermediate Certificate Authority (CA)' },
        days    : 365 * 5,
        flags   : [],
        extensions:
        {
          basicConstraints        : 'critical,CA:TRUE,pathlen:0',
          keyUsage                : 'critical,keyCertSign,cRLSign',
          subjectKeyIdentifier    : 'hash',
          authorityKeyIdentifier  : 'keyid:always,issuer:always',
        }
      }, config)

      const { dns, ip, extensions: { nameConstraints } } = config
      config.extensions.nameConstraints = nameConstraints || this.#conformNameConstraints(dns, ip)

      config.flags.push(`-CA <(echo "${ca.cert}")`)
      config.flags.push(`-CAkey <(echo "${ca.key}")`)

      const
        sslOptions  = this.#conformSslOptions(config),
        sslArgs     = '-new -out /dev/stdout -keyout /dev/stdout -text -batch -multivalue-rdn',
        result      = await this.#exec(`openssl req ${sslArgs} -days ${config.days} ${sslOptions}`, config.timeout)

      return this.#conformPemCert(result)
    }
    catch(reason)
    {
      const error = new Error(`Failed to create intermediate certificate authority (ICA)`)
      error.code  = 'E_TLS_OPENSSL_INTERMEDIATE'
      error.cause = reason
      throw error
    }
  }

  /**
   * Create an end-entity certificate.
   * @param {Certificate} ca
   * @param {Config} config
   * @returns {Certificate}
   * @throws {Error} E_TLS_OPENSSL_LEAF
   */
  async leaf(ca, config)
  {
    try
    {
      config = Object.assign(
      {
        subject : { CN:'End-Entity Certificate' },
        days    : 365,
        flags   : [],
        extensions:
        {
          basicConstraints        : 'CA:FALSE',
          keyUsage                : 'critical,digitalSignature,keyEncipherment',
          subjectKeyIdentifier    : 'hash',
          authorityKeyIdentifier  : 'keyid:always,issuer:always',
          extendedKeyUsage        : config?.usage ?? 'serverAuth,clientAuth'
        }
      }, config)

      const { dns, ip, extensions: { subjectAltName } } = config
      config.extensions.subjectAltName = subjectAltName || this.#conformSan(dns, ip)

      config.flags.push(`-CA <(echo "${ca.cert}")`)
      config.flags.push(`-CAkey <(echo "${ca.key}")`)

      const
        sslOptions  = this.#conformSslOptions(config),
        sslArgs     = '-new -out /dev/stdout -keyout /dev/stdout -text -batch -multivalue-rdn',
        result      = await this.#exec(`openssl req ${sslArgs} -days ${config.days} ${sslOptions}`, config.timeout)

      return this.#conformPemCert(result)
    }
    catch(reason)
    {
      const error = new Error(`Failed to create end-entity certificate`)
      error.code  = 'E_TLS_OPENSSL_LEAF'
      error.cause = reason.stderr || reason
      throw error
    }
  }

  serverCert(ca, config = {})
  {
    return this.leaf(ca, { ...config, usage:'serverAuth' })
  }

  clientCert(ca, config = {})
  {
    return this.leaf(ca, { ...config, usage:'clientAuth' })
  }

  verify = new Proxy(this.#verify.bind(this, 3),
  {
    get: (_, prop) =>
    {
      switch(prop)
      {
        case 'basic'    : return this.#verify.bind(this, 0)
        case 'weak'     : return this.#verify.bind(this, 1)
        case 'average'  : return this.#verify.bind(this, 2)
        case 'strong'   : return this.#verify.bind(this, 4)
        case 'robust'   : return this.#verify.bind(this, 5)
        default         :
        {
          const error = new Error(`Unknown verification level ${prop}`)
          error.code  = 'E_TLS_OPENSSL_VERIFY'
          error.cause = `The level must be one of the following: basic, weak, average, strong, robust`
          throw error
        }
      }
    }
  })

  async #verify(level, cert, ...ca)
  {
    try
    {
      const
        chain   = ca.length 
                ? `<(cat ${ca.map((ca) => `<(echo "${ca.cert}")`).join(' ')})` 
                : `<(echo "${cert.cert}")`,
        args    = `-x509_strict -policy_check -auth_level ${level}`,
        result  = await this.#exec(`openssl verify ${args} -CAfile ${chain} <(echo "${cert.cert}")`),
        status  = result.stdout.trim().endsWith('OK')

      return status
    }
    catch(reason)
    {
      const error = new Error(`Failed to verify certificate at level ${level}`)
      error.code  = 'E_TLS_OPENSSL_VERIFY'
      error.cause = reason.stderr || reason
      throw error
    }
  }

  async #exec(cmd, timeout=5e3)
  {
    try
    {
      const 
        abortExec = new AbortController(),
        timeoutId = setTimeout(() => abortExec.abort(new Error('Timeout')), timeout),
        result    = await asyncExec(cmd, { signal:abortExec.signal, shell:'/bin/bash' })
  
      clearTimeout(timeoutId)
  
      return result
    }
    catch(reason)
    {
      const error = new Error(`Failed to execute openssl command`)
      error.code  = 'E_TLS_OPENSSL_EXEC'
      error.cause = reason
      error.cmd   = cmd
      throw error
    }
  }

  #conformSslOptions(config)
  {
    config = Object.assign(
    {
      algorithm : OpenSSL.ALGO.EdDSAEd25519, 
      hash      : OpenSSL.HASH.SHA256,
      flags     : [] 
    }, config)

    const
      extensions  = this.#conformExtensions(config.extensions),
      algorithm   = this.#conformAlgo(config.algorithm),
      hash        = this.#conformHash(config.hash),
      password    = this.#conformPassword(config.password),
      subject     = this.#conformSubject(config.subject),
      newkey      = `-newkey ${algorithm}`,
      sslOptions  = [...config.flags,newkey,hash,password,subject,...extensions].filter(Boolean).join(' ')

    return sslOptions
  }

  #conformPemCert({ stdout, stderr })
  {
    const
      isEncrypted = stdout.includes('ENCRYPTED PRIVATE KEY'),
      headerKey   = isEncrypted ? 'BEGIN ENCRYPTED PRIVATE KEY' : 'BEGIN PRIVATE KEY',
      footerKey   = isEncrypted ? 'END ENCRYPTED PRIVATE KEY'   : 'END PRIVATE KEY',
      headerCert  = 'BEGIN CERTIFICATE',
      footerCert  = 'END CERTIFICATE'

    const
      PEM       = (delimiter) => `-----${delimiter}-----`,
      beginKey  = stdout.indexOf( PEM(headerKey)  ),
      endKey    = stdout.indexOf( PEM(footerKey)  ),
      beginCert = stdout.indexOf( PEM(headerCert) ),
      endCert   = stdout.indexOf( PEM(footerCert) ),
      beginText = stdout.indexOf('Certificate:'),
      endText   = stdout.indexOf('-----', beginText),
      key       = stdout.slice(beginKey,  endKey  + footerKey.length  + 11),
      cert      = stdout.slice(beginCert, endCert + footerCert.length + 11),
      text      = stdout.slice(beginText, endText).trim(),
      meta      = stderr.trim()

    return { key, cert, text, meta }
  }

  #conformPassword(password)
  {
    const
      escape  = (pass) => pass.replace(/["`\\]/g, '\\$&'),
      passout = 'string' === typeof password ? password : password?.output,
      passin  = 'string' === typeof password ? password : password?.input,
      output  = passout ? `-passout pass:"${escape(passout)}"` : '-nodes',
      input   = passin && `-passin pass:"${escape(passin)}"`

    return [output, input].filter(Boolean).join(' ')
  }

  #conformSubject(subject = {})
  {
    const
      keyValueMap = (key) => (val) => `/${key}=${val}`,
      normalize   = (val) => Array.isArray(val) ? val : [val],
      subjectMap  = ([ key, val ]) => normalize(val).map(keyValueMap(key)).join('')

    subject = Object.entries(subject)
    subject = subject.map(subjectMap).join('')
    subject = subject ? `-subj "${subject}"` : ''

    return subject
  }

  #conformExtensions(extensions)
  {
    extensions = Object.entries(extensions)
    extensions = extensions.filter(([, val]) => val)
    extensions = extensions.map(([key, val]) => `${key}=${val}`)
    extensions = extensions.map((extension)  => `-addext "${extension}"`)
    return extensions
  }

  #conformHash(hash)
  {
    switch(hash)
    {
      case OpenSSL.HASH.SHA1:
      case OpenSSL.HASH.SHA224:
      case OpenSSL.HASH.SHA256:
      case OpenSSL.HASH.SHA384:
      case OpenSSL.HASH.SHA512:
      {
        return `-${hash}`
      }
      default:
      {
        const error = new Error(`Unknown hash ${hash}`) 
        error.code  = 'E_TLS_OPENSSL_UNKNOWN_HASH'
        error.cause = `The hash must be one of the following: ${Object.values(OpenSSL.HASH).join(', ')}`
        throw error
      }
    }
  }

  #conformAlgo(algorithm)
  {
    switch(algorithm)
    {
      case OpenSSL.ALGO.ECDSAP256:
      case OpenSSL.ALGO.ECDSAP384:
      case OpenSSL.ALGO.ECDSAP521:
      {
        return 'ec -pkeyopt ec_paramgen_curve:' + algorithm.split(':')[1]
      }
      case OpenSSL.ALGO.EdDSAEd25519:
      case OpenSSL.ALGO.EdDSAEd448:
      {
        return algorithm.split(':')[1].toLowerCase()
      }
      case OpenSSL.ALGO.RSA2048:
      case OpenSSL.ALGO.RSA4096:
      default:
      {
        return algorithm.toLowerCase()
      }
    }
  }

  /**
   * Standard way to specify domain names in certificates.
   * If this is set as critical, then the certificate is invalid if the host is not in the list. 
   * This is a non standard definition that is not supported by all clients.
   * 
   * @param {String[]} dns
   * @param {String[]} ip
   * @param {Boolean}  critical
   * @returns {string}
   */
  #conformSan(dns=['localhost'], ip=['127.0.0.1'], critical=true)
  {
    critical = critical ? 'critical,' : ''

    return dns.length || ip.length
      ? critical + dns.map((dns) => 'DNS:'+dns).concat(ip.map((ip) => 'IP:'+ip)).join(',')
      : ''
  }

  /**
   * Which hosts are permitted to be signed by the certificate.
   * Required by RFC 5280 to be marked as critical to ensure clients strictly enforce the constraints.
   * OBS! "nameConstraints" requires a legacy netmask format.
   * 
   * @param {String[]} dns
   * @param {String[]} ip
   * @returns {string}
   */
  #conformNameConstraints(dns=['localhost'], ip=['127.0.0.1'])
  {
    ip = ip.map((ip) => ip + '/255.255.255.255')
    return dns.length || ip.length
      ? 'critical,'+dns.map((dns) => 'DNS:'+dns).concat(ip.map((ip) => 'IP:'+ip)).map((item) => 'permitted;'+item).join(',')
      : ''
  }
}