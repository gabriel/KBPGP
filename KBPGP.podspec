Pod::Spec.new do |s|

  s.name         = "KBPGP"
  s.version      = "0.1.4"
  s.summary      = "kbpgp for iOS/OSX."
  s.homepage     = "https://github.com/gabriel/KBPGP"
  s.license      = { :type => "MIT" }
  s.author       = { "Gabriel Handford" => "gabrielh@gmail.com" }
  s.source       = { :git => "https://github.com/gabriel/KBPGP.git", :tag => s.version.to_s }
  s.dependency 'NAChloride'
  s.dependency 'ObjectiveSugar'
  s.dependency 'GHKit'
  s.dependency 'Mantle'
  s.dependency 'TSTripleSec'
  s.dependency 'GHBigNum'
  s.dependency 'KBKeybase/Core'

  s.source_files = 'KBPGP/**/*.{c,h,m}'
  s.requires_arc = true

  s.ios.platform = :ios, "8.0"
  s.ios.deployment_target = "8.0"

  s.osx.platform = :osx, "10.10"

  s.resources = ["js/keybase*.js"]

end
