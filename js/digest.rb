require "digest"

files = ["keybase.js", "keybase-kbpgp-jscore.js"]

files.each do |file|
  puts file
  puts Digest::SHA512.hexdigest(File.read(file))
end
