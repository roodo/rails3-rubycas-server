#encoding: utf-8

require 'active_record'
require 'active_record/base'


module CASServer::Model

  module Consumable
    def consume!
      self.consumed = Time.now
      self.save!
    end

    def self.included(mod)
      mod.extend(ClassMethods)
    end

    module ClassMethods
      def cleanup(max_lifetime, max_unconsumed_lifetime)
        transaction do
          conditions = ["created_on < ? OR (consumed IS NULL AND created_on < ?)",
                          Time.now - max_lifetime,
                          Time.now - max_unconsumed_lifetime]
          expired_tickets_count = count(:conditions => conditions)

          Rails.logger.debug("Destroying #{expired_tickets_count} expired #{self.name.demodulize}"+
            "#{'s' if expired_tickets_count > 1}.") if expired_tickets_count > 0

          destroy_all(conditions)
        end
      end
    end
  end

  class Base < ActiveRecord::Base
  end
  
  class User < ActiveRecord::Base
  end
  
  class Ticket < Base
    def to_s
      ticket
    end

    def self.cleanup(max_lifetime)
      transaction do
        conditions = ["created_on < ?", Time.now - max_lifetime]
        expired_tickets_count = count(:conditions => conditions)

        Rails.logger.debug("Destroying #{expired_tickets_count} expired #{self.name.demodulize}"+
          "#{'s' if expired_tickets_count > 1}.") if expired_tickets_count > 0

        destroy_all(conditions)
      end
    end
  end

  class LoginTicket < Ticket
    set_table_name 'casserver_lts'
    include Consumable
  end

  class ServiceTicket < Ticket
    set_table_name 'casserver_sts'
    include Consumable

    belongs_to :granted_by_tgt,
      :class_name => 'CASServer::Model::TicketGrantingTicket',
      :foreign_key => :granted_by_tgt_id
    has_one :proxy_granting_ticket,
      :foreign_key => :created_by_st_id

    def matches_service?(service)
      CASServer::CAS.clean_service_url(self.service) ==
        CASServer::CAS.clean_service_url(service)
    end
  end

  class ProxyTicket < ServiceTicket
    belongs_to :granted_by_pgt,
      :class_name => 'CASServer::Model::ProxyGrantingTicket',
      :foreign_key => :granted_by_pgt_id
  end

  class TicketGrantingTicket < Ticket
    set_table_name 'casserver_tgts'

    serialize :extra_attributes

    has_many :granted_service_tickets,
      :class_name => 'CASServer::Model::ServiceTicket',
      :foreign_key => :granted_by_tgt_id
  end

  class ProxyGrantingTicket < Ticket
    set_table_name 'casserver_pgts'
    belongs_to :service_ticket
    has_many :granted_proxy_tickets,
      :class_name => 'CASServer::Model::ProxyTicket',
      :foreign_key => :granted_by_pgt_id
  end

  class Error
    attr_reader :code, :message

    def initialize(code, message)
      @code = code
      @message = message
    end

    def to_s
      message
    end
  end
end
