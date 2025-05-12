# Função 1: Captura de Dados
# Captura o tráfego de rede em tempo real e salva em formato PCAP para análise posterior.

# Função 2: Conversão PCAP → CSV
# Converte arquivos PCAP para CSV, facilitando a análise com ferramentas de ciência de dados.

import subprocess
import os

def capturar_em_tempo_real(interface, duracao, arquivo_saida):
    print(f"Capturando tráfego da interface {interface} por {duracao} segundos...")
    if not os.access(arquivo_saida, os.W_OK):
        print(f"Erro: Não tenho permissão para gravar o arquivo {arquivo_saida}.")
        print("Veja este link: https://www.techlanda.com/2020/02/tshark-file-to-which-capture-would-be.html")
        exit()
        return
    cmd = ['tshark', '-i', interface, '-a', f'duration:{duracao}', '-w', arquivo_saida]
    subprocess.run(cmd)
    print(f"Captura salva em: {arquivo_saida}")
    return arquivo_saida

def converter_pcap_para_csv(arquivo_pcap, arquivo_csv):
    print(f"Convertendo {arquivo_pcap} para {arquivo_csv}...")
    fields = [
        '-e', 'frame.time_epoch',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'eth.src',
        '-e', 'eth.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'frame.len',
        '-e', 'ip.proto'
    ]
    display_filter = 'tcp or udp'
    cmd = [
        'tshark',
        '-r', arquivo_pcap,
        '-Y', display_filter,
        '-T', 'fields',
        *fields,
        '-E', 'separator=,',
        '-E', 'header=y'
    ]
    with open(arquivo_csv, 'w') as f:
        subprocess.run(cmd, stdout=f)
    print(f"CSV gerado com sucesso: {arquivo_csv}")

# Interação com o usuário
print("Escolha uma opção:")
print("1 - Capturar tráfego da rede em tempo real")
print("2 - Converter um arquivo PCAP existente para CSV")
opcao = input("Digite 1 ou 2: ")

if opcao == '1':
    interface = input("Informe a interface de rede (ex: eth0, wlan0): ")
    duracao = input("Duração da captura (em segundos): ")
    arquivo_pcap = './captura/captura.pcap'
    capturar_em_tempo_real(interface, duracao, arquivo_pcap)
    output_csv = f'saida_{arquivo_pcap}.csv'
    converter_pcap_para_csv(arquivo_pcap, output_csv)

elif opcao == '2':
    input_pcap = input("Informe o caminho do arquivo .pcap (ex: /home/usuario/Downloads/trafego.pcap): ")
    output_csv = f"saida_{input_pcap.split('/')[-1]}.csv"
    converter_pcap_para_csv(input_pcap, output_csv)

else:
    print("Opção inválida. Encerrando.")