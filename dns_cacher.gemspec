Gem::Specification.new do |s|
  s.name = "dns_cacher"
  s.version = "0.1.0"
  s.license = "GPL-3.0"

  s.summary = "A minimal and lightweight local DNS/mDNS caching server"

  s.authors = [ "truffle" ]
  s.email = ["truffle074@gmail.com"]

  s.metadata["source_code_uri"] = "https://github.com/truffle0/dns_cacher"

  s.files = Dir.glob("lib/**/*.rb")
  s.bindir = "bin"
  s.executables = Dir.glob("bin/*").map{|f| File.basename(f)}

  s.add_dependency("async", "~>2.8")
  s.add_dependency("rb-inotify", "~>0.11")
end
