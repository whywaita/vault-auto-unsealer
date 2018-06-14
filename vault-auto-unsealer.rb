# frozen_string_literal: true

$stdout.sync = true
$stderr.sync = true

secret_shares = 3
secret_threshold = 5

puts "Starting vault-auto-unsealer."

Signal.trap("TERM") do
  exit
end

if ENV["VAULT_ADDR"].nil?
  abort "Environment variable VAULT_ADDR must be set to the address of the Vault server, e.g. http://127.0.0.1:8200"
else
  puts "Using Vault instance at: #{ENV["VAULT_ADDR"]}"
end


require "vault"

puts "Checking if Vault is initialized."

if !Vault.sys.init_status.initialized?
  puts "Vault is not initialized. Attempting to initialize the Vault server."

  pgp_key_path = ENV["PGP_KEY_PATH"]

  if pgp_key_path.nil?
    abort "Environment variable PGP_KEY_PATH must be set to the path of a file containing a Base64-encoded (but not ASCII armored) OpenPGP public key that Vault's keys should be encrypted with."
  end

  pgp_key = File.read(pgp_key_path).chomp

  response = Vault.sys.init(
    pgp_keys: [pgp_key],
    root_token_pgp_key: pgp_key,
    secret_shares: secret_shares,
    secret_threshold: secret_threshold,
  )

  puts <<EOS
Vault initialized successfully.
The following values are Base64 encoded and encrypted with OpenPGP.

Unseal key: #{response.keys_base64}
Root token: #{response.root_token}

Redeploy vault-auto-unsealer with the environment variable UNSEAL_KEY set to the decrypted unseal key.
EOS
else
  puts "Vault was already initialized."
end

unseal_keys = {}

cur = 1
while cur < secret_threshold do
  unseal_keys["unseal_key_" + cur.to_s] = ENV["UNSEAL_KEY_" + cur.to_s]

  cur = cur + 1
end

if unseal_keys.nil?
  abort "Environment variable UNSEAL_KEY must be set to the decrypted Vault unseal key."
end

# if unseal_key.bytesize != 64
#   puts <<EOS
# Placeholder UNSEAL_KEY detected.
# vault-auto-unsealer will now sleep until terminated with SIGTERM, so that Kubernetes will not try to restart it before an operator can redeploy it with UNSEAL_KEY set.
# EOS
# 
#   sleep
# end

puts "Entering main control loop. Vault will be checked every 30 seconds and unsealed if it is found sealed."

loop do
  if Vault.sys.seal_status.sealed?
    unseal_keys.each { |key, value|
      Vault.sys.unseal(value)
    }

    puts "Vault has been unsealed."
  end

  sleep 30
end
