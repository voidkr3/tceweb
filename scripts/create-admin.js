'use strict';
require('dotenv').config();
const { neon } = require('@neondatabase/serverless');
const bcrypt = require('bcryptjs');
const readline = require('node:readline/promises');
const { stdin: input, stdout: output } = require('node:process');
(async()=>{
 if(!process.env.DATABASE_URL)throw new Error('Configure DATABASE_URL no arquivo .env.');
 const rl=readline.createInterface({input,output});
 try{
  const name=(await rl.question('Nome do coordenador principal: ')).trim();
  const email=(await rl.question('E-mail institucional: ')).trim().toLowerCase();
  const password=await rl.question('Senha inicial (mínimo 8 caracteres, maiúscula, minúscula e número): ');
  if(name.length<2||!/^\S+@\S+\.\S+$/.test(email)||password.length<8||!/[A-Z]/.test(password)||!/[a-z]/.test(password)||!/[0-9]/.test(password))throw new Error('Dados inválidos. Verifique nome, e-mail e requisitos da senha.');
  const sql=neon(process.env.DATABASE_URL);const hash=await bcrypt.hash(password,12);
  const rows=await sql`INSERT INTO users(name,email,password_hash,role,must_change_password) VALUES (${name},${email},${hash},'coordenador',true) RETURNING id,email,role`;
  console.log('Conta administrativa criada:',rows[0]);console.log('No primeiro acesso, será obrigatório definir uma nova senha.');
 }finally{rl.close()}
})().catch(e=>{console.error('Falha ao criar administrador:',e.message);process.exit(1)});
