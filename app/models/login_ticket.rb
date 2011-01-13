#encoding: utf-8

require 'model'

class LoginTicket < ActiveRecord::Base
  include CASServer::Model::Consumable
  include CASServer::Model::Common
end
