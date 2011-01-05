# encoding: utf-8


require 'casclient'
require 'casclient/frameworks/rails/filter'

CASClient::Frameworks::Rails::Filter.configure(
  :cas_base_url => 'http://localhost:3000/',
  :login_url => "http://localhost:3000/server/index",
  :logout_url => "http://localhost:3000/server/logout",
  :validate_url  => "http://localhost:3000/server/proxyValidate",
)
