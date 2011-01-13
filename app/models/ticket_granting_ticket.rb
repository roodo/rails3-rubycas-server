#encoding: utf-8

require 'model'

class TicketGrantingTicket < ActiveRecord::Base
  include CASServer::Model::Consumable
  include CASServer::Model::Common

  serialize :extra_attributes

  has_many :granted_service_tickets,
    :class_name => 'ServiceTicket',
    :foreign_key => :granted_by_tgt_id
end
