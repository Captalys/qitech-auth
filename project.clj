(defproject qitech-auth "1.0.3"
  :description "QI-TECH sign/unsign requests"
  :url "http://github.com/wandersoncferreira/qitech-auth"
  :license {:name "EPL-2.0 OR GPL-2.0-or-later WITH Classpath-exception-2.0"
            :url "https://www.eclipse.org/legal/epl-2.0/"}
  :dependencies [[org.clojure/clojure "1.10.0"]
                 [clj-time "0.15.2"]
                 [cheshire "5.9.0"]
                 [http-kit "2.4.0-alpha3"]
                 [buddy/buddy-sign "3.1.0"]]
  :repl-options {:init-ns qitech-auth.core})
