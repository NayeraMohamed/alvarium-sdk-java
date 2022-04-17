
/*******************************************************************************
 * Copyright 2022 Dell Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 *******************************************************************************/

package com.alvarium.annotators;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.nio.file.Path;

import com.alvarium.annotators.http.ParseResult;
import com.alvarium.annotators.http.ParseResultException;
import com.alvarium.contracts.Annotation;
import com.alvarium.contracts.AnnotationType;
import com.alvarium.hash.HashType;
import com.alvarium.sign.KeyInfo;
import com.alvarium.sign.SignException;
import com.alvarium.sign.SignProvider;
import com.alvarium.sign.SignProviderFactory;
import com.alvarium.sign.SignatureInfo;
import com.alvarium.sign.SignType;
import com.alvarium.utils.Encoder;
import com.alvarium.utils.PropertyBag;

import org.apache.http.client.methods.HttpUriRequest;

class PkiHttpAnnotator extends AbstractAnnotator implements Annotator {
  private final HashType hash;
  private SignatureInfo signature;
  private final AnnotationType kind;

  protected PkiHttpAnnotator(HashType hash, SignatureInfo signature) {
    this.hash = hash;
    this.signature = signature;
    this.kind = AnnotationType.PKIHttp;
  }

  public Annotation execute(PropertyBag ctx, byte[] data) throws AnnotatorException {
    final String key = super.deriveHash(hash, data);

    String host;
    try {
      host = InetAddress.getLocalHost().getHostName();
    } catch (UnknownHostException e) {
      throw new AnnotatorException("Cannot get host name", e);
    }

    HttpUriRequest request = ctx.getProperty(AnnotationType.PKIHttp.name(), HttpUriRequest.class);
    ParseResult parsed; 
    try {
      parsed = new ParseResult(request);
    } catch (URISyntaxException e) {
      throw new AnnotatorException("Invalid request URI", e);
    } catch (ParseResultException e) {
      throw new AnnotatorException("Error parsing the request", e);
    }
    final Signable signable = new Signable(parsed.getSeed(), parsed.getSignature());

    // Use the parsed request to obtain the key name and type we should use to
    // validate the signature
    Path path = Paths.get(signature.getPublicKey().getPath());
    Path directory = path.getParent();
    String publicKeyPath = String.join("/", directory.toString(), parsed.getKeyid());

    SignType alg;
    try {
      alg = SignType.fromString(parsed.getAlgorithm());
    } catch (EnumConstantNotPresentException e) {
      throw new AnnotatorException("Invalid key type" + parsed.getAlgorithm());
    }
    KeyInfo publicKey = new KeyInfo(publicKeyPath, alg);
    signature = new SignatureInfo(publicKey, signature.getPrivateKey());

    Boolean isSatisfied = verifySignature(signature.getPublicKey(), signable);

    final Annotation annotation = new Annotation(
        key,
        hash,
        host,
        kind,
        null,
        isSatisfied,
        Instant.now());

    final String annotationSignature = super.signAnnotation(signature.getPrivateKey(), annotation);
    annotation.setSignature(annotationSignature);
    return annotation;
  }

  /**
   * Responsible for verifying the signature, returns true if the verification
   * passed, false otherwise.
   * 
   * @param key      The public key used to verify the signature
   * @param signable Contains the data (seed) and signature
   * @return True if signature valid, false otherwise
   * @throws AnnotatorException
   */
  private Boolean verifySignature(KeyInfo key, Signable signable) throws AnnotatorException {
    final SignProviderFactory signFactory = new SignProviderFactory();
    final SignProvider signProvider;
    try {
      signProvider = signFactory.getProvider(key.getType());
    } catch (SignException e) {
      throw new AnnotatorException("Could not instantiate signing provider", e);
    }

    try {
      // Load public key
      final String publicKeyPath = key.getPath();
      final String publicKey = Files.readString(
          Paths.get(publicKeyPath),
          StandardCharsets.US_ASCII);

      // Verify signature
      signProvider.verify(
          Encoder.hexToBytes(publicKey),
          signable.getSeed().getBytes(),
          Encoder.hexToBytes(signable.getSignature()));

      return true;
    } catch (SignException e) {
      return false;
    } catch (IOException e) {
      throw new AnnotatorException("Failed to load public key", e);
    }

  }
}
