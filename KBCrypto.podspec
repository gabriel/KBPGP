Pod::Spec.new do |s|

  s.name         = "KBCrypto"
  s.version      = "0.1.1"
  s.summary      = "PGP for iOS/OSX."
  s.homepage     = "https://github.com/gabriel/KBCrypto"
  s.license      = { :type => "MIT" }
  s.author       = { "Gabriel Handford" => "gabrielh@gmail.com" }
  s.source       = { :git => "https://github.com/gabriel/KBCrypto.git", :tag => "0.1.1" }
  s.dependency 'NAChloride'
  s.dependency 'ObjectiveSugar'
  s.dependency 'GHKit'
  s.source_files = 'KBCrypto/**/*.{c,h,m}'
  s.requires_arc = true

end
