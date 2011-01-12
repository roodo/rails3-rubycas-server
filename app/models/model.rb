#encoding: utf-8

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
