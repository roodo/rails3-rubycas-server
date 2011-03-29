# encoding: utf-8

module ServerHelper

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

  def serialize_extra_attribute(builder, key, value)
    if value.kind_of?(String)
      builder.tag! key, value
    elsif value.kind_of?(Numeric)
      builder.tag! key, value.to_s
    else
      builder.tag! key do
        builder.cdata! value.to_yaml
      end
    end
  end

  def compile_template(engine, data, options, views)
    super engine, data, options, @custom_views || views
  rescue Errno::ENOENT
    raise unless @custom_views
    super engine, data, options, views
  end

end
