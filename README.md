# qitech-auth [![Clojars Project](https://img.shields.io/clojars/v/qitech-auth.svg)](https://clojars.org/qitech-auth)

A Clojure library designed to help users to build valid
requests to QI TECH services.

## Installation

Leinigen/Boot

```clj
[qitech-auth "1.0.3"]
```

Clojure CLI/deps.edn
```clj
qitech-auth {:mvn/version "1.0.3"}
```

Maven
```clj
<dependency>
  <groupId>qitech-auth</groupId>
  <artifactId>qitech-auth</artifactId>
  <version>1.0.3</version>
</dependency>
```

## Usage

There is a small setup to perform before using this API. You
have to provide the keys as environment variable as follows:

```bash
export QI_PUBLIC_KEY=$(base64 qitech.key.pub)
export CLIENT_API_KEY="1331a7-3212-23123-3102-231axcaj2312"
export CLIENT_PRIVATE_KEY=$(base64 your_private.key)
```

The API is small and there are only two functions `sign` and `unsign`.

```clj
(require '[qitech-auth.core :as q])

(def data-signed (q/sign {:method "GET"
                          :endpoint "https://api-auth.sandbox.qitech.app/test/{api-key}"}))

;; => {:request-header ....  :request-body ...}

;;; or
(def data-signed (q/sign {:method "POST"
                          :content-type "application/json"
                          :body {:data "all-your-payload"}
                          :endpoint "https://api-auth.sandbox.qitech.app/test/{api-key}"}))

(def ret (http/post url {:body (:request-body data-signed)
                         :headers (:request-header data-signed)}))
(def ret-unsigned (q/unsign ret)) ;; => {:data "all-your-payload"}
```

You can test if everything is working fine by calling the next method:

```clj
(require '[qitech-auth.core :as q])

(q/test-endpoints)
```


## License

Copyright © 2020 Wanderson Ferreira.

This program and the accompanying materials are made available under the
terms of the Eclipse Public License 2.0 which is available at
http://www.eclipse.org/legal/epl-2.0.

This Source Code may also be made available under the following Secondary
Licenses when the conditions for such availability set forth in the Eclipse
Public License, v. 2.0 are satisfied: GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or (at your
option) any later version, with the GNU Classpath Exception which is available
at https://www.gnu.org/software/classpath/license.html.
