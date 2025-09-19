@echo off
echo =========================
echo 1. Ativando ambiente Conda...
call conda activate virtual-environment-2

echo =========================
echo 2. Instalando dependências do backend...
pip install -r backend\requirements.txt

echo =========================
echo 3. Instalando dependências do frontend...
cd frontend
npm install

echo =========================
echo 4. Build do frontend...
npm run build
cd ..

echo =========================
echo 5. TorchServe
torchserve --stop
torchserve --start --ncs --model-store backend\model_store --models autoencoder=autoencoder.mar --enable-model-api --disable-token-auth

echo =========================
echo 6. Iniciando backend Flask...
cd backend

IF "%MONGO_URI%"=="" (
    echo ERRO: variável MONGO_URI não definida!
    echo Defina com: setx MONGO_URI "mongodb+srv://usuario:senha@clusterwatermark.xx5bmdq.mongodb.net/watermark"
    exit /b 1
)

python app.py
pause
