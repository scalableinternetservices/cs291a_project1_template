# frozen_string_literal: true

require 'json'
require 'jwt'
require 'pp'

def main(event:, context:)
  # You shouldn't need to use context, but its fields are explained here:
  # https://docs.aws.amazon.com/lambda/latest/dg/ruby-context.html
  response(body: event, status: 200)
end

def create_response(body: nil, status: 200)
  {
      body: body ? body.to_json + "\n" : '',
      statusCode: status
  }
end

def response(body: nil, status: 200)
  body["headers"] = normalize_http_headers(body["headers"])
  case body["path"]
  when "/token"
    begin
      # only POST method allowed for /token
      unless validate_http_method(body, ["POST"])
        return create_response(status: 405)
      end
      if body['headers']['content-type'] != 'application/json'
        return create_response(status: 415)
      end
      # check if the POST body is a valid json
      unless valid_json(body["body"])
        return create_response(status: 422)
      end
      # Generate the token
      payload = {
          data: JSON.parse(body["body"]),
          exp: Time.now.to_i + 5,
          nbf: Time.now.to_i + 2
      }
      token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
      return create_response(body: {:token => token}, status: 201)

    rescue Exception => e
      p "Exception in POST", e
    end

  when "/"
    unless validate_http_method(body, ["GET"])
      return create_response(status: 405)
    end
    unless validate_auth_header(body)
      return create_response(status: 403)
    end
    return process_return_token(body)
  else
    return create_response(status: 404)
  end
end

def validate_auth_header(body)
  if body['headers'].has_key?("authorization") && body["headers"]["authorization"].include?("Bearer ")
    return true
  end
  p "invalid auth header", body['headers']
  false
end

def normalize_http_headers(body)
  new_hash = {}
  body.each_pair do |k, v|
    new_hash.merge!({k.downcase => v})
  end
  new_hash
end

def validate_http_method(body, expected_methods)
  if body.key?("httpMethod")
    if expected_methods.include? body["httpMethod"]
      return true
    end
  end
  false
end

def process_return_token(body)
  begin
    bearer_token = body["headers"]["authorization"]
    token = bearer_token.split("Bearer ")[1]
    # fetch the content of the data field in the JWT token
    decoded_token = JWT.decode token, ENV['JWT_SECRET'], {algorithm: 'HS256'}
    return create_response(body: decoded_token[0]['data'], status: 200)
  rescue JWT::ExpiredSignature => e
    return create_response(body: e.message, status: 401)
  rescue JWT::ImmatureSignature => e
    return create_response(body: e.message, status: 401)
  rescue JWT::DecodeError => e
    return create_response(body: e.message, status: 403)
  end
end

def valid_json(json)
  begin
    json_obj = JSON.parse(json)
    return true
  rescue Exception => _e
    p "FALSE!!!"
    return false
  end
end

if $PROGRAM_NAME == __FILE__
  # If you run this file directly via `ruby function.rb` the following code
  # will execute. You can use the code below to help you test your functions
  # without needing to deploy first.
  #
  ENV['JWT_SECRET'] = '10454447'

  # Call /token
  PP.pp main(context: {}, event: {
      #'body' => '{',
      'body' => '{"name": "bboe"}',
      'headers' => {'Content-Type' => 'application/json'},
      'httpMethod' => 'POST',
      'path' => '/token'
  })

  # Generate a token
  payload = {
      data: {user_id: 128},
      exp: Time.now.to_i + 1,
      nbf: Time.now.to_i
  }
  token = JWT.encode payload, ENV['JWT_SECRET'], 'HS256'
  # Call /
  PP.pp main(context: {}, event: {
      'headers' => {'Authorization' => "Bearer #{token}",
                    'Content-Type' => 'application/json'},
      'httpMethod' => 'GET',
      'path' => '/'
  })
end
