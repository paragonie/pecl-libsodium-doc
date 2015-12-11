## Introduction to Libsodium Development in PHP

This e-book is intended for PHP developers with no prior cryptography 
experience. To that end, we will not go too in-depth to the nature of the lower-level 
cryptography features that each libsodium feature uses.

Towards the end of each chapter, we will link to other resources that explain 
the finer details for readers that are interested.

Let's jump right in, shall we?

<h3 id="what-is-libsodium">What is Libsodium?</h3>

(Copied from the [Official Libsodium Documentation](https://download.libsodium.org/doc/).)

**The Sodium crypto library ([libsodium](https://github.com/jedisct1/libsodium))** 
is a modern, easy-to-use software library for encryption, decryption,
signatures, password hashing and more.

It is a portable, cross-compilable, installable, packageable fork of [NaCl](http://nacl.cr.yp.to),
with a compatible API, and an extended API to improve usability even further.

Its goal is to provide all of the core operations needed to build higher-level
cryptographic tools.

Sodium supports a variety of compilers and operating systems, including Windows
(with MinGW or Visual Studio, x86 and x64), iOS and Android.

The design choices emphasize security, and "magic constants" have clear rationales.

And despite the emphasis on high security, primitives are faster across-the-board
than most implementations of the NIST standards.

[Version 1.0.7](https://github.com/jedisct1/libsodium/releases) was released on 
December 9, 2015.

#### What is PECL Libsodium?

PECL Libsodium refers to the [PHP extension](https://pecl.php.net/package/libsodium)
available as a PECL package that exposes the libsodium API for PHP developers.

There are two important things to keep in mind here:

1. The PECL package doesn't work unless you install libsodium. You need both.
2. Just because libsodium has a feature doesn't mean it's available (or intended)
   for use by PHP developers.

<h3 id="terms-concepts">Terms and Concepts</h3>

The remaining pages will proceed under the assumption that you have read these terms
and and understood [basic cryptography concepts](https://paragonie.com/blog/2015/08/you-wouldnt-base64-a-password-cryptography-decoded).

* **Cryptography**:  
  A subset of computer science that focuses on secure communication.
* **Key**:  
  In cryptography, a key is a piece of information that determines the output of
  a cryptographic algorithm.
* **Nonce**:  
  A number that should only be used once (i.e. for a given key or set of keys).
* **Cryptographic hash functions** (hashes):  
  A deterministic one-way transformation of variable-length data into a fixed-size
  output -- by itself, a hash function does not use a key.
* **Secret-key Cryptography**:  
  Cryptographic algorithms and protocols where both participants share the same 
  secret key.
* **Public-key Cryptography**:  
  Cryptographic algorithms and protocols where each participant possesses a 
  private key and a related public key.
  
  Their private key is never shared; their public key is. The public key is always 
  mathematically related to the private key, such that someone possessing the
  private key can generate the correct public key, but the opposite is not
  practical.
* **Encryption**:  
  The reversible transformation of data, with the use of one or more keys, to 
  ensure the only someone possessing the correct key can read the contents of a
  given message.
* **Authentication**:  
  Provides assurance that a message was sent by someone in possession of the 
  secret authentication key.
* **Digital Signature**:  
  Calculated from a message and a private key; allows anyone in possession of 
  the message, signature, and public key to verify that a particular message is
  authentic.

<h3 id="installing-libsodium">Installing Libsodium and the PHP extension</h3>

#### Installing Libsodium

On Debian >= 8 and Ubuntu >= 15.04, libsodium can be installed with:

    apt-get install libsodium-dev

If you're running an older LTS version of Ubuntu (e.g. 12.04), you can use one
of these PPAs to get libsodium installed:

* [https://answers.launchpad.net/~chris-lea/+archive/ubuntu/libsodium](https://answers.launchpad.net/~chris-lea/+archive/ubuntu/libsodium)
* [https://launchpad.net/~anton+/+archive/ubuntu/dnscrypt](https://launchpad.net/~anton+/+archive/ubuntu/dnscrypt)

For example:

    # If this doesn't work...
        sudo add-apt-repository ppa:chris-lea/libsodium
    # Run these two lines instead...
        sudo echo "deb http://ppa.launchpad.net/chris-lea/libsodium/ubuntu precise main" >> /etc/apt/sources.list
        sudo echo "deb-src http://ppa.launchpad.net/chris-lea/libsodium/ubuntu precise main" >> /etc/apt/sources.list
    # Finally...
    sudo apt-get update && sudo apt-get install libsodium-dev

On OSX, libsodium can be installed with

    brew install libsodium

On Fedora, libsodium can be installed with:

    dnf install libsodium-devel

On RHEL, CentOS,  libsodium can be installed from EPEL repository with:

    yum install libsodium-devel

---------------------------

If your operating system (or OS version) isn't listed above, you may have to go
through the trouble of [manually installing libsodium](https://download.libsodium.org/doc/installation/index.html).

#### Installing the PHP Extension via PECL

If you don't have the PECL package manager installed on your system, make sure
you do that first. There are guides for installing PECL available on the 
Internet for virtually every operating system that PHP supports.

Once you have libsodium installed on your system, the next thing to do is to 
install the PHP extension. The easiest way to do this is to install the PECL
package.

You can get PECL libsodium by running this command.

    pecl install libsodium

And add the following line to your `php.ini` file:

    extension=libsodium.so

You might be able to achieve this result by running `php5enmod libsodium`,
depending on which webserver you use. Make sure you restart your webserver after
installing PECL libsodium.

### Verifying your Libsodium Version

After installing both the library and the PHP extension, make a quick test script to verify that you have the correct version of libsodium installed.

    <?php
    var_dump([
        \Sodium\library_version_major(),
        \Sodium\library_version_minor()
    ]);

If you're using libsodium 1.0.6, you should see this when you run this test 
script:

    user@hostname:~/dir$ php version_check.php
    array(2) {
      [0] =>
      int(8)
      [1] =>
      int(0)
    }

If you get different numbers, you won't have access to some of the features that
should be in libsodium 1.0.6. If you need them, you'll need to go through the
ritual of compiling from source instead:

    git clone https://github.com/jedisct1/libsodium.git
    cd libsodium
    git checkout tags/1.0.6
    ./autogen.sh
    ./configure && make distcheck
    sudo make install

Then run `pecl uninstall libsodium` and `pecl install libsodium`. When you run
the version check PHP script again, you should see the correct numbers.

### Extra Information

* [Installing PECL Packages on Ubuntu](http://askubuntu.com/a/403348/260704)
* [The Official Libsodium Documentation](https://download.libsodium.org/doc)
* [Libsodium on Github](https://github.com/jedisct1/libsodium)
* [PECL Libsodium on Github](https://github.com/jedisct1/libsodium-php)
