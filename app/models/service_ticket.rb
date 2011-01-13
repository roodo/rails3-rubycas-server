#encoding: utf-8

require 'model'

class ServiceTicket < ActiveRecord::Base
  include CASServer::Model::Consumable
  include CASServer::Model::Common
  
  belongs_to :granted_by_tgt,
    :class_name => 'TicketGrantingTicket',
    :foreign_key => :granted_by_tgt_id
    
  has_one :proxy_granting_ticket,
    :foreign_key => :created_by_st_id
end
