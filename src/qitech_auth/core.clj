(ns qitech-auth.core
  (:require [clojure.string :as cstr]
            [clj-time.local :as l]
            [clj-time.format :as f]
            [clojure.spec.alpha :as s]
            [buddy.sign.jwt :as jwt]
            [buddy.core.keys :as keys]
            [org.httpkit.client :as http]
            [cheshire.core :as json])
  (:import java.util.Base64
           java.security.MessageDigest))

(s/def ::method #{"GET" "POST" "PUT" "OPTION"})
(s/def ::content-type string?)
(s/def ::endpoint string?)
(s/def ::body map?)
(s/def ::file string?)
(s/def ::client-api-key string?)

(s/def ::input
  (s/keys :req-un [::method
                   ::endpoint]
          :opt-un [::content-type
                   ::client-api-key
                   ::body
                   ::file]))

(defn- read-pkey [pkey]
  (let [env-data (or (System/getenv pkey) "")
        base64 (cstr/replace env-data #"\s" "")
        base64 (cstr/replace base64 "\n" "")]
    (if (empty? base64)
      (throw (ex-info (format "No %s key was found!" (cstr/upper-case pkey)) {:pkey pkey}))
      (->> base64
           (.decode (Base64/getDecoder))
           slurp))))

(defn- get-keys
  []
  {:qi-public-key (keys/str->public-key (read-pkey "QI_PUBLIC_KEY"))
   :client-private-key (keys/str->private-key (read-pkey "CLIENT_PRIVATE_KEY"))
   :client-api-key (System/getenv "CLIENT_API_KEY")})

(defn- encode-body
  [{:keys [body client-private-key]}]
  (when body
    (jwt/sign body client-private-key {:alg :es512})))

(defn- now-gmt
  []
  (str (f/unparse (f/formatter "E, d MMM y H:m:s") (l/local-now)) " GMT"))

(defn- md5 [^String s]
  (let [algorithm (MessageDigest/getInstance "MD5")
        raw (.digest algorithm (.getBytes s))]
    (format "%032x" (BigInteger. 1 raw))))

(defn- encode-header
  [{:keys [method content-type endpoint md5-body client-api-key client-private-key]}]
  (let [now (now-gmt)
        headers {"alg" "ES512" "typ" "JWT"}
        claims {:sub client-api-key
                :signature (str method "\n" md5-body "\n" content-type "\n" now "\n" endpoint)}]
    (jwt/sign claims client-private-key {:alg :es512
                                         :headers headers})))

(defn sign
  "Get either headers and body already secured with QI-TECH mechanism of authentication.

  Example of an input data:

  {:method \"GET\"
   :endpoint test-endpoint}

  {:content-type \"application/json\"
   :method \"POST\"
   :client-api-key \"string\"
   :body {:testing \"more-data\"}
   :endpoint test-endpoint}
  "
  [input]
  {:pre [(s/valid? ::input input)]}
  (let [keys (get-keys)
        client-api-key (or (:client-api-key input) (:client-api-key keys))
        encoded-body (encode-body (merge keys input))
        md5-body (cond
                   (some? (:file input)) (md5 (:file input))
                   (nil? encoded-body) ""
                   :else (md5 encoded-body))
        encoded-header-token (encode-header (->> md5-body
                                                 (assoc (merge keys input)
                                                        :md5-body)))]
    {:request-header {"Authorization" (str "QIT" " " client-api-key ":" encoded-header-token)
                      "API-CLIENT-KEY" client-api-key}
     :request-body (json/generate-string {:encoded_body encoded-body})}))

(defn unsign
  "Return the `body` informed by QI-TECH in their response object.

  :qi-response     Entire response map with headers and body received from QI-TECH
  :client-api-key  Product-based key from QI-TECH."
  ([qi-response]
   (unsign qi-response (:client-api-key (get-keys))))
  ([qi-response client-api-key]
   (let [{:keys [qi-public-key]} (get-keys)
         auth (:authorization (:headers qi-response))
         auth-splitted (cstr/split auth #":")
         auth-unsigned (jwt/unsign (second auth-splitted) qi-public-key {:alg :es512})
         body (get (json/parse-string (:body qi-response)) "encoded_body")]

     ;; validate qi-response against sensible security expectations
     (letfn [(build-error [which?]
               (case which?
                 :wrong-auth (ex-info "Wrong format for the Authorization header" {})
                 :wrong-api (ex-info "The api_key gathered on message's authorization header does not match the one provided to the function" {})
                 :wrong-md5 (ex-info "The 'md5_body' parameter on message's signature does not match the 'body' provided to the function." {})))]
       (cond
         (not= (count (cstr/split auth #":")) 2) (throw (build-error :wrong-auth))
         (not= client-api-key (second (cstr/split (first auth-splitted) #" "))) (throw (build-error :wrong-api))
         (not= (md5 body) (second (cstr/split (:signature auth-unsigned) #"\n"))) (throw (build-error :wrong-md5))))

     (jwt/unsign body qi-public-key {:alg :es512}))))

(defn test-endpoints
  "This function must guarantee that our `sign` methodology is correct.

  It's done two requests to QI-Tech in their /test/{api-key} endpoint using GET and POST methods
  
  :client-api-key    Product-based key from QI-TECH."
  ([]
   (test-endpoints (:client-api-key (get-keys))))
  ([client-api-key]
   (let [auth-endpoint "https://api-auth.sandbox.qitech.app"
         test-endpoint (str "/test/" client-api-key)
         get-payload {:method "GET"
                      :endpoint test-endpoint}
         post-payload {:content-type "application/json"
                       :method "POST"
                       :body {:testing "more-data"}
                       :endpoint test-endpoint}
         get-ret (http/get (str auth-endpoint test-endpoint)
                           {:headers (:request-header (sign get-payload))})
         signed-post-payload (sign post-payload)
         post-ret (http/post (str auth-endpoint test-endpoint)
                             {:headers (:request-header signed-post-payload)
                              :body (:request-body signed-post-payload)})]

     (when-not (= (:status @get-ret) 200)
       (throw (ex-info "The implementation changed from QITECH side! (or yours, what you did?)" {})))

     {:get-response (unsign @get-ret client-api-key)
      :post-response (unsign @post-ret client-api-key)})))
