#encoding: utf-8

require 'model'

class ProxyGrantingTicket < ActiveRecord::Base
  include CASServer::Model::Consumable
  include CASServer::Model::Common
  
  belongs_to :service_ticket
  
  has_many :granted_proxy_tickets,
    :class_name => 'ProxyTicket',
    :foreign_key => :granted_by_pgt_id
end
