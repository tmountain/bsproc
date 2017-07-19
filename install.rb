require "rbconfig"
require "ftools"

include Config

version = CONFIG["MAJOR"] + "." + CONFIG["MINOR"]
sitedir = CONFIG["sitedir"]
dest    = "#{sitedir}/#{version}"
File.install("bayespam.rb", dest)
