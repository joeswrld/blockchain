import hashlib
import json
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import base64
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS


class Wallet:
    """
    Wallet class for generating addresses and signing transactions
    """
    def __init__(self):
        # Generate RSA key pair (2048 bits)
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()
        
    def get_address(self):
        """
        Generate wallet address from public key
        Returns a base64 encoded string
        """
        public_key_bytes = self.public_key.export_key()
        address = hashlib.sha256(public_key_bytes).hexdigest()
        return address
    
    def sign_transaction(self, transaction):
        """
        Sign a transaction with private key
        """
        transaction_string = json.dumps(transaction, sort_keys=True).encode()
        hash_obj = SHA256.new(transaction_string)
        signature = pkcs1_15.new(self.private_key).sign(hash_obj)
        return base64.b64encode(signature).decode()
    
    def export_keys(self):
        """
        Export keys for backup
        """
        return {
            'private_key': self.private_key.export_key().decode(),
            'public_key': self.public_key.export_key().decode(),
            'address': self.get_address()
        }
    
    @staticmethod
    def import_keys(private_key_string):
        """
        Import wallet from private key
        """
        wallet = Wallet()
        wallet.private_key = RSA.import_key(private_key_string)
        wallet.public_key = wallet.private_key.publickey()
        return wallet


class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()
        self.wallets = {}  # Store wallets: address -> balance

        # Create the genesis block
        self.new_block(previous_hash='1', proof=100)

    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')

    def valid_chain(self, chain):
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            print(f'{last_block}')
            print(f'{block}')
            print("\n-----------\n")
            
            last_block_hash = self.hash(last_block)
            if block['previous_hash'] != last_block_hash:
                return False

            if not self.valid_proof(last_block['proof'], block['proof'], last_block_hash):
                return False

            last_block = block
            current_index += 1

        return True

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbours:
            response = requests.get(f'http://{node}/chain')

            if response.status_code == 200:
                length = response.json()['length']
                chain = response.json()['chain']

                if length > max_length and self.valid_chain(chain):
                    max_length = length
                    new_chain = chain

        if new_chain:
            self.chain = new_chain
            return True

        return False

    def new_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time(),
            'transactions': self.current_transactions,
            'proof': proof,
            'previous_hash': previous_hash or self.hash(self.chain[-1]),
        }

        # Update balances based on transactions
        for transaction in self.current_transactions:
            sender = transaction['sender']
            recipient = transaction['recipient']
            amount = transaction['amount']
            
            if sender != "0":  # Not a mining reward
                self.wallets[sender] = self.wallets.get(sender, 0) - amount
            
            self.wallets[recipient] = self.wallets.get(recipient, 0) + amount

        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, sender, recipient, amount, signature=None):
        """
        Creates a new transaction
        For mining rewards, sender is "0" and signature is not required
        """
        # Validate transaction
        if sender != "0":
            # Check if sender has sufficient balance
            if self.get_balance(sender) < amount:
                raise ValueError("Insufficient balance")
            
            # Verify signature (in production, you'd verify the actual signature)
            if not signature:
                raise ValueError("Transaction must be signed")
        
        transaction = {
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
            'signature': signature
        }
        
        self.current_transactions.append(transaction)
        return self.last_block['index'] + 1

    def get_balance(self, address):
        """
        Calculate balance for an address
        """
        return self.wallets.get(address, 0)

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_block):
        last_proof = last_block['proof']
        last_hash = self.hash(last_block)

        proof = 0
        while self.valid_proof(last_proof, proof, last_hash) is False:
            proof += 1

        return proof

    @staticmethod
    def valid_proof(last_proof, proof, last_hash):
        guess = f'{last_proof}{proof}{last_hash}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"


# Instantiate the Node
app = Flask(__name__)
CORS(app)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

# Instantiate the Blockchain
blockchain = Blockchain()

# Store for created wallets (in production, users manage their own keys)
created_wallets = {}


@app.route('/wallet/new', methods=['GET'])
def new_wallet():
    """
    Create a new wallet
    """
    wallet = Wallet()
    wallet_data = wallet.export_keys()
    
    # Store wallet (in production, users keep their private keys!)
    address = wallet.get_address()
    created_wallets[address] = wallet
    
    response = {
        'message': 'New wallet created',
        'address': address,
        'private_key': wallet_data['private_key'],
        'public_key': wallet_data['public_key'],
        'warning': 'SAVE YOUR PRIVATE KEY! You will need it to sign transactions.'
    }
    return jsonify(response), 201


@app.route('/wallet/balance/<address>', methods=['GET'])
def get_balance(address):
    """
    Get balance for a wallet address
    """
    balance = blockchain.get_balance(address)
    
    response = {
        'address': address,
        'balance': balance
    }
    return jsonify(response), 200


@app.route('/mine', methods=['GET'])
def mine():
    """
    Mine a new block
    """
    last_block = blockchain.last_block
    proof = blockchain.proof_of_work(last_block)

    # Mining reward
    blockchain.new_transaction(
        sender="0",
        recipient=node_identifier,
        amount=1,
    )

    previous_hash = blockchain.hash(last_block)
    block = blockchain.new_block(proof, previous_hash)

    response = {
        'message': "New Block Forged",
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'miner_reward': 1
    }
    return jsonify(response), 200


@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    """
    Create a new transaction
    Requires: sender, recipient, amount, signature
    """
    values = request.get_json()

    required = ['sender', 'recipient', 'amount']
    if not all(k in values for k in required):
        return 'Missing values', 400

    # Check if signature is provided (not needed for mining rewards)
    signature = values.get('signature')
    
    try:
        index = blockchain.new_transaction(
            values['sender'], 
            values['recipient'], 
            values['amount'],
            signature
        )
        
        response = {'message': f'Transaction will be added to Block {index}'}
        return jsonify(response), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@app.route('/transactions/send', methods=['POST'])
def send_transaction():
    """
    Send coins from one wallet to another (with automatic signing)
    Requires: sender_address, recipient_address, amount, private_key
    """
    values = request.get_json()
    
    required = ['sender_address', 'recipient_address', 'amount', 'private_key']
    if not all(k in values for k in required):
        return 'Missing values', 400
    
    try:
        # Import wallet from private key
        wallet = Wallet.import_keys(values['private_key'])
        
        # Verify the sender address matches the private key
        if wallet.get_address() != values['sender_address']:
            return jsonify({'error': 'Private key does not match sender address'}), 400
        
        # Create transaction data
        transaction_data = {
            'sender': values['sender_address'],
            'recipient': values['recipient_address'],
            'amount': values['amount']
        }
        
        # Sign the transaction
        signature = wallet.sign_transaction(transaction_data)
        
        # Add transaction to blockchain
        index = blockchain.new_transaction(
            values['sender_address'],
            values['recipient_address'],
            values['amount'],
            signature
        )
        
        response = {
            'message': f'Transaction will be added to Block {index}',
            'transaction': {
                'sender': values['sender_address'],
                'recipient': values['recipient_address'],
                'amount': values['amount'],
                'signature': signature
            }
        }
        return jsonify(response), 201
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Transaction failed: {str(e)}'}), 400


@app.route('/chain', methods=['GET'])
def full_chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200


@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    
    if nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201


@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': blockchain.chain
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': blockchain.chain
        }

    return jsonify(response), 200


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser()
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on')
    args = parser.parse_args()
    port = args.port

    app.run(host='0.0.0.0', port=port)