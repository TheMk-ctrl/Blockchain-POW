import hashlib
import json
import time
import rsa
import os
import binascii
import requests
from typing import List, Dict, Any, Set
from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import uvicorn

# --- КРИПТОГРАФИЧЕСКАЯ И СТРУКТУРНАЯ ЧАСТЬ ---

class Transaction:
    def __init__(self, sender_address: str, recipient_address: str, amount: float):
        self.sender_address = sender_address
        self.recipient_address = recipient_address
        self.amount = amount
        self.timestamp = time.time()
        self.signature = ""

    def calculate_hash(self) -> str:
        tx_content = f"{self.sender_address}{self.recipient_address}{self.amount}{self.timestamp}"
        return hashlib.sha256(tx_content.encode('utf-8')).hexdigest()

    def sign_transaction(self, private_key: rsa.PrivateKey):
        if self.sender_address == "System":
            return True
        tx_hash = self.calculate_hash()
        signature = rsa.sign(tx_hash.encode('utf-8'), private_key, 'SHA-256')
        self.signature = binascii.hexlify(signature).decode('utf-8')

    def is_valid(self) -> bool:
        if self.sender_address == "System":
            return True
        if not self.signature:
            return False
        try:
            public_key = rsa.PublicKey.load_pkcs1(self.sender_address.encode('utf-8'))
            tx_hash = self.calculate_hash()
            signature_bytes = binascii.unhexlify(self.signature)
            rsa.verify(tx_hash.encode('utf-8'), signature_bytes, public_key)
            return True
        except Exception:
            return False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sender_address": self.sender_address,
            "recipient_address": self.recipient_address,
            "amount": self.amount,
            "timestamp": self.timestamp,
            "signature": self.signature
        }

class Block:
    def __init__(self, index: int, transactions: List[Transaction], previous_hash: str = ""):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        block_content = {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        block_string = json.dumps(block_content, sort_keys=True).encode('utf-8')
        return hashlib.sha256(block_string).hexdigest()

    def mine_block(self, difficulty: int):
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash
        }

class Blockchain:
    def __init__(self, port: int):
        self.port = port
        self.db_file = f"blockchain_{port}.json"
        self.chain: List[Block] = []
        self.pending_transactions: List[Transaction] = []
        self.nodes: Set[str] = set()  # Хранит адреса соседних узлов
        self.difficulty = 3
        self.mining_reward = 50.0

        if os.path.exists(self.db_file):
            self.load_chain()
        else:
            genesis_block = Block(0, [], "0")
            genesis_block.mine_block(self.difficulty)
            self.chain.append(genesis_block)
            self.save_chain()

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def register_node(self, address: str):
        """Добавляет новый узел в список соседей (например, 'http://127.0.0.1:8001')."""
        if address.endswith("/"):
            address = address[:-1]
        self.nodes.add(address)

    def mine_pending_transactions(self, mining_reward_address: str) -> Block:
        reward_tx = Transaction("System", mining_reward_address, self.mining_reward)
        self.pending_transactions.append(reward_tx)

        new_block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions,
            previous_hash=self.get_latest_block().hash
        )
        new_block.mine_block(self.difficulty)
        
        self.chain.append(new_block)
        self.pending_transactions = []
        self.save_chain()
        return new_block

    def add_transaction(self, transaction: Transaction):
        if not transaction.is_valid():
            raise ValueError("Транзакция не прошла валидацию подписи!")
        self.pending_transactions.append(transaction)

    def is_chain_valid(self, chain_to_validate: List[Block] = None) -> bool:
        """Проверяет переданную цепь или собственную цепь по умолчанию."""
        chain = chain_to_validate if chain_to_validate is not None else self.chain
        
        for i in range(1, len(chain)):
            current = chain[i]
            previous = chain[i - 1]

            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
            for tx in current.transactions:
                if not tx.is_valid():
                    return False
        return True

    def resolve_conflicts(self) -> bool:
        """Алгоритм консенсуса: ищет самую длинную валидную цепь в сети."""
        longest_chain = None
        max_length = len(self.chain)

        for node in self.nodes:
            try:
                response = requests.get(f"{node}/chain", timeout=3)
                if response.status_code == 200:
                    data = response.json()
                    length = data["length"]
                    chain_data = data["chain"]

                    # Парсим входящую цепь в объекты Block и Transaction
                    parsed_chain = []
                    for b_data in chain_data:
                        txs = []
                        for t_data in b_data["transactions"]:
                            t = Transaction(t_data["sender_address"], t_data["recipient_address"], t_data["amount"])
                            t.timestamp = t_data["timestamp"]
                            t.signature = t_data["signature"]
                            txs.append(t)
                        
                        b = Block(b_data["index"], txs, b_data["previous_hash"])
                        b.timestamp = b_data["timestamp"]
                        b.nonce = b_data["nonce"]
                        b.hash = b_data["hash"]
                        parsed_chain.append(b)

                    # Если чужая цепь длиннее и при этом валидна — запоминаем её
                    if length > max_length and self.is_chain_valid(parsed_chain):
                        max_length = length
                        longest_chain = parsed_chain
            except requests.RequestException:
                continue # Если узел недоступен, просто пропускаем его

        if longest_chain:
            self.chain = longest_chain
            self.save_chain()
            return True # Наша цепь заменена на более актуальную
        return False

    def save_chain(self):
        data = [block.to_dict() for block in self.chain]
        with open(self.db_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)

    def load_chain(self):
        with open(self.db_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.chain = []
        for block_data in data:
            transactions = []
            for tx_data in block_data["transactions"]:
                tx = Transaction(tx_data["sender_address"], tx_data["recipient_address"], tx_data["amount"])
                tx.timestamp = tx_data["timestamp"]
                tx.signature = tx_data["signature"]
                transactions.append(tx)
            block = Block(block_data["index"], transactions, block_data["previous_hash"])
            block.timestamp = block_data["timestamp"]
            block.nonce = block_data["nonce"]
            block.hash = block_data["hash"]
            self.chain.append(block)


# --- СЕТЕВАЯ ЧАСТЬ (FastAPI) ---

app = FastAPI()
blockchain: Blockchain = None  # Инициализируется при старте сервера

class TransactionSchema(BaseModel):
    sender_address: str
    recipient_address: str
    amount: float
    timestamp: float
    signature: str

class NodeRegisterSchema(BaseModel):
    urls: List[str]

@app.get("/chain")
def get_chain():
    """Возвращает всю цепь блоков текущего узла."""
    return {
        "chain": [block.to_dict() for block in blockchain.chain],
        "length": len(blockchain.chain)
    }

@app.post("/transactions/new")
def new_transaction(tx_data: TransactionSchema):
    """Добавляет новую транзакцию в пул ожидания."""
    tx = Transaction(tx_data.sender_address, tx_data.recipient_address, tx_data.amount)
    tx.timestamp = tx_data.timestamp
    tx.signature = tx_data.signature
    
    try:
        blockchain.add_transaction(tx)
        return {"message": "Транзакция успешно верифицирована и добавлена в пул."}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/mine")
def mine(miner_address: str):
    """Запускает процесс майнинга для накопленных транзакций."""
    block = blockchain.mine_pending_transactions(miner_address)
    return {
        "message": "Новый блок успешно добыт!",
        "block_index": block.index,
        "hash": block.hash,
        "transactions_count": len(block.transactions)
    }

@app.post("/nodes/register")
def register_nodes(data: NodeRegisterSchema):
    """Регистрирует адреса соседних узлов."""
    if not data.urls:
        raise HTTPException(status_code=400, detail="Список URL не может быть пустым.")
    for url in data.urls:
        blockchain.register_node(url)
    return {
        "message": "Новые узлы успешно добавлены.",
        "total_nodes": list(blockchain.nodes)
    }

@app.get("/nodes/resolve")
def consensus():
    """Синхронизирует данные сети, запрашивая цепи у соседей."""
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return {"message": "Наша цепь была устаревшей и заменилась на более длинную цепь из сети.", "chain": [b.to_dict() for b in blockchain.chain]}
    return {"message": "Наша цепь актуальна (является самой длинной).", "chain": [b.to_dict() for b in blockchain.chain]}


if __name__ == "__main__":
    import sys
    # Считываем порт из аргументов командной строки (по умолчанию 8000)
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    
    # Инициализируем блокчейн индивидуально для этого порта
    blockchain = Blockchain(port=port)
    
    print(f"Запуск узла блокчейна на порту {port}...")
    uvicorn.run(app, host="127.0.0.1", port=port)