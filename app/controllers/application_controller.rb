#encoding: utf-8


class ApplicationController < ActionController::Base
  protect_from_forgery
  
  def response_status_from_error(error)
    case error.code.to_s
    when /^INVALID_/, 'BAD_PGT'
      422
    when 'INTERNAL_ERROR'
      500
    else
      500
    end
  end
  
  def serialize_extra_attribute(builder, value)
    if value.kind_of?(String)
      builder.text! value
    elsif value.kind_of?(Numeric)
      builder.text! value.to_s
    else
      builder.cdata! value.to_yaml
    end
  end
end
