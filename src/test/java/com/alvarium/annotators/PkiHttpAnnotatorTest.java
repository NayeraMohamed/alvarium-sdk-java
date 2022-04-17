
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

import java.util.HashMap;
import java.util.Date;
import java.io.UnsupportedEncodingException;
import java.net.URI;

import com.alvarium.SdkInfo;
import com.alvarium.annotators.http.Ed2551Handler;
import com.alvarium.annotators.http.HandlerException;
import com.alvarium.contracts.Annotation;
import com.alvarium.contracts.AnnotationType;
import com.alvarium.contracts.DerivedComponent;
import com.alvarium.hash.HashInfo;
import com.alvarium.hash.HashType;
import com.alvarium.sign.KeyInfo;
import com.alvarium.sign.SignType;
import com.alvarium.sign.SignatureInfo;
import com.alvarium.utils.ImmutablePropertyBag;
import com.alvarium.utils.PropertyBag;

import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class PkiHttpAnnotatorTest {

        @Test
        // Tests the Signature signed by the assembler
        public void executeShouldGetSatisfiedAnnotation() throws AnnotatorException, HandlerException {
                final AnnotatorFactory annotatorFactory = new AnnotatorFactory();
                final KeyInfo pubKey = new KeyInfo("./src/test/java/com/alvarium/annotators/public.key",
                                SignType.Ed25519);
                final KeyInfo privKey = new KeyInfo("./src/test/java/com/alvarium/annotators/private.key",
                                SignType.Ed25519);
                final SignatureInfo sigInfo = new SignatureInfo(pubKey, privKey);

                final byte[] data = String.format("{key: \"test\"}").getBytes();

                Date date = new Date();
                HttpPost request = new HttpPost(URI.create("http://example.com/foo?var1=&var2=2"));
                request.setHeader("Date", date.toString());
                request.setHeader("Content-Type", "application/json");
                request.setHeader("Content-Length", "10");
                try {
                        request.setEntity(new StringEntity("{key: \"test\"}"));
                } catch (UnsupportedEncodingException e) {
                        throw new AnnotatorException("Unsupported Character Encoding", e);

                }

                String[] fields = { DerivedComponent.METHOD.getValue(),
                                    DerivedComponent.PATH.getValue(),
                                    DerivedComponent.AUTHORITY.getValue(),
                                "Content-Type", "Content-Length" };

                Ed2551Handler requestHandler = new Ed2551Handler(request);
                requestHandler.addSignatureHeaders(date, fields, sigInfo);

                HashMap<String, Object> map = new HashMap<>();
                map.put(AnnotationType.PKIHttp.name(), request);
                final PropertyBag ctx = new ImmutablePropertyBag(map);

                final AnnotationType[] annotators = { AnnotationType.PKIHttp };
                final SdkInfo config = new SdkInfo(annotators, new HashInfo(HashType.SHA256Hash), sigInfo, null);
                final Annotator annotator = annotatorFactory.getAnnotator(AnnotationType.PKIHttp, config);
                final Annotation annotation = annotator.execute(ctx, data);
                assertTrue("isSatisfied should be true", annotation.getIsSatisfied());
        }

        @Test
        public void executeShouldGetUnsatisfiedAnnotation() throws AnnotatorException, HandlerException {
                final AnnotatorFactory annotatorFactory = new AnnotatorFactory();
                final KeyInfo pubKey = new KeyInfo("./src/test/java/com/alvarium/annotators/public.key",
                                SignType.Ed25519);
                final KeyInfo privKey = new KeyInfo("./src/test/java/com/alvarium/annotators/private.key",
                                SignType.Ed25519);
                final SignatureInfo sigInfo = new SignatureInfo(pubKey, privKey);

                final String signature = "A9E41596541933DB7144CFBF72105E4E53F9493729CA66331A658B1B18AC6DF5DA991"
                                + "AD9720FD46A664918DFC745DE2F4F1F8C29FF71209B2DA79DFD1A34F50C";

                final byte[] data = String.format("{key: \"test\"}").getBytes();

                Date date = new Date();
                HttpPost request = new HttpPost(URI.create("http://example.com/foo?var1=&var2=2"));
                request.setHeader("Date", date.toString());
                request.setHeader("Content-Type", "application/json");
                request.setHeader("Content-Length", "10");
                try {
                        request.setEntity(new StringEntity("{key: \"test\"}"));
                } catch (UnsupportedEncodingException e) {
                        throw new AnnotatorException("Unsupported Character Encoding", e);

                }

                String[] fields = { DerivedComponent.METHOD.getValue(),
                                    DerivedComponent.PATH.getValue(),
                                    DerivedComponent.AUTHORITY.getValue(),
                                "Content-Type", "Content-Length" };

                Ed2551Handler requestHandler = new Ed2551Handler(request);

                requestHandler.addSignatureHeaders(date, fields, sigInfo);

                request.setHeader("Signature", signature);

                HashMap<String, Object> map = new HashMap<>();
                map.put(AnnotationType.PKIHttp.name(), request);
                final PropertyBag ctx = new ImmutablePropertyBag(map);

                final AnnotationType[] annotators = { AnnotationType.PKIHttp };
                final SdkInfo config = new SdkInfo(annotators, new HashInfo(HashType.SHA256Hash), sigInfo, null);
                final Annotator annotator = annotatorFactory.getAnnotator(AnnotationType.PKIHttp, config);
                final Annotation annotation = annotator.execute(ctx, data);
                assertFalse("isSatisfied should be false", annotation.getIsSatisfied());
        }
}
