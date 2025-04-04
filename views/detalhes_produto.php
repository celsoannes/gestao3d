<?php
session_start();
require __DIR__ . '/../config/config.php';
require __DIR__ . '/../includes/menu.php';

if (!isset($_SESSION['usuario_id'])) {
    header("Location: login.php");
    exit;
}

// Obter o ID do produto
$id = isset($_GET['id']) ? intval($_GET['id']) : 0;

// Buscar os detalhes do produto
$stmt = $pdo->prepare("
    SELECT p.*, c.nome AS categoria_nome 
    FROM produtos p
    LEFT JOIN categorias c ON p.categoria_id = c.id
    WHERE p.id = ?
");
$stmt->execute([$id]);
$produto = $stmt->fetch();

// Se o produto não for encontrado, redireciona de volta
if (!$produto) {
    header("Location: index.php");
    exit;
}

// Buscar as imagens adicionais do produto
$stmt_imagens = $pdo->prepare("SELECT caminho_imagem FROM produto_imagens WHERE produto_id = ?");
$stmt_imagens->execute([$id]);
$imagens_adicionais = $stmt_imagens->fetchAll(PDO::FETCH_ASSOC);

// Buscar as peças associadas ao produto e calcular os custos
$stmt_pecas = $pdo->prepare("
    SELECT p.id AS peca_id, p.nome AS nome_peca, p.imagem AS imagem_peca, p.material AS material_peca, 
           p.quantidade_material, p.tempo_impressao, i.Marca AS marca_impressora, i.Modelo AS modelo_impressora, 
           i.Tipo AS tipo_impressora, i.Localizacao AS localizacao_impressora, i.kWh AS consumo_impressora,
           t.Prestadora, t.kWh AS kWh_energia, t.ICMS, t.PIS_PASEP, t.COFINS, t.TOTAL_horas,
           i.Valor_do_Bem, i.Tempo_de_Vida_Util, pr.lucro AS lucro_produto,
           el.Marca AS marca_estacao, el.Modelo AS modelo_estacao, el.kWh AS consumo_estacao,
           el.tempo_lavagem, el.tempo_cura, el.Valor_do_Bem AS valor_estacao, el.Tempo_de_Vida_Util AS vida_util_estacao,
           l.Valor_Litro AS valor_lavagem, l.Fator_Consumo AS fator_consumo_lavagem,
           pp.quantidade AS quantidade_peca,
           c.nome AS categoria_nome -- Adicionando a categoria da peça
    FROM pecas p
    JOIN impressoras i ON p.impressora = i.ID
    JOIN produtos_pecas pp ON p.id = pp.peca_id
    JOIN tabela_energia t ON 1=1
    JOIN produtos pr ON pp.produto_id = pr.id
    LEFT JOIN estacoes_lavagem el ON 1=1 -- Assumindo que há apenas uma estação de lavagem
    LEFT JOIN lavagem l ON el.lavagem_id = l.id
    LEFT JOIN categorias c ON pr.categoria_id = c.id -- Join para buscar a categoria
    WHERE pp.produto_id = ?
");
$stmt_pecas->execute([$id]);
$pecas = $stmt_pecas->fetchAll();

// Buscar as tags associadas ao produto
$stmt_tags = $pdo->prepare("
    SELECT t.nome 
    FROM tags t
    JOIN produto_tags pt ON t.id = pt.tag_id
    WHERE pt.produto_id = ?
");
$stmt_tags->execute([$id]);
$tags = $stmt_tags->fetchAll(PDO::FETCH_ASSOC);

// Função para calcular o custo de energia da lavagem e cura
function calcularCustoEnergiaLavagem($consumo_estacao, $tempo_lavagem, $tempo_cura, $kWh_energia, $ICMS, $PIS_PASEP, $COFINS, $TOTAL_horas) {
    // Converter tempo de lavagem e cura para minutos
    list($lav_horas, $lav_minutos, $lav_segundos) = explode(":", $tempo_lavagem);
    $tempo_lavagem_minutos = ($lav_horas * 60) + $lav_minutos + ($lav_segundos / 60);

    list($cura_horas, $cura_minutos, $cura_segundos) = explode(":", $tempo_cura);
    $tempo_cura_minutos = ($cura_horas * 60) + $cura_minutos + ($cura_segundos / 60);

    // Calcular o custo de energia
    $custo_kWh = $TOTAL_horas + ($TOTAL_horas * ($ICMS / 100)) + ($TOTAL_horas * ($PIS_PASEP / 100)) + ($TOTAL_horas * ($COFINS / 100));
    return ($consumo_estacao * ($tempo_lavagem_minutos + $tempo_cura_minutos) / 60) * $custo_kWh;
}

// Função para calcular o custo de material de lavagem
function calcularCustoMaterialLavagem($quantidade_material, $valor_lavagem, $fator_consumo_lavagem) {
    // 1g de material = 1ml de líquido de lavagem
    $quantidade_lavagem_ml = $quantidade_material * $fator_consumo_lavagem;
    return $quantidade_lavagem_ml;
}

// Função para calcular a depreciação/manutenção da estação de lavagem
function calcularDepreciacaoLavagem($tempo_lavagem, $tempo_cura, $valor_estacao, $vida_util_estacao) {
    // Converter tempo de lavagem e cura para minutos
    list($lav_horas, $lav_minutos, $lav_segundos) = explode(":", $tempo_lavagem);
    $tempo_lavagem_minutos = ($lav_horas * 60) + $lav_minutos + ($lav_segundos / 60);

    list($cura_horas, $cura_minutos, $cura_segundos) = explode(":", $tempo_cura);
    $tempo_cura_minutos = ($cura_horas * 60) + $cura_minutos + ($cura_segundos / 60);

    return ($valor_estacao / ($vida_util_estacao * 60)) * ($tempo_lavagem_minutos + $tempo_cura_minutos);
}

// Buscar os componentes associados ao produto
$stmt_componentes = $pdo->prepare("SELECT c.nome_material, c.tipo_material, c.descricao, c.unidade_medida, c.preco_unitario, c.fornecedor, c.observacoes, c.caminho_imagem, c.id
    FROM componentes c
    JOIN produtos_componentes pc ON c.id = pc.componente_id
    WHERE pc.produto_id = ?");
$stmt_componentes->execute([$id]);
$componentes = $stmt_componentes->fetchAll();

// Função para calcular o custo de energia
function calcularCustoEnergia($consumo_impressora, $tempo_impressao, $kWh_energia, $ICMS, $PIS_PASEP, $COFINS, $TOTAL_horas) {
    list($horas, $minutos, $segundos) = explode(":", $tempo_impressao);
    $tempo_impressao_minutos = ($horas * 60) + $minutos + ($segundos / 60);
    $custo_kWh = $TOTAL_horas + ($TOTAL_horas * ($ICMS / 100)) + ($TOTAL_horas * ($PIS_PASEP / 100)) + ($TOTAL_horas * ($COFINS / 100));
    return ($consumo_impressora * $tempo_impressao_minutos / 60) * $custo_kWh;
}

// Função para calcular o custo por quilo do material
function calcularCustoMaterial($tipo_impressora, $material_peca, $quantidade_material) {
    global $pdo;
    
    if ($tipo_impressora == 'Filamento') {
        $stmt_filamento = $pdo->prepare("SELECT Valor_Kg FROM filamentos WHERE Tipo = ?");
        $stmt_filamento->execute([$material_peca]);
        $filamento = $stmt_filamento->fetch();
        $valor_kg = $filamento['Valor_Kg'];
    } else {
        $stmt_resina = $pdo->prepare("SELECT Valor_Kg FROM resinas WHERE Tipo = ?");
        $stmt_resina->execute([$material_peca]);
        $resina = $stmt_resina->fetch();
        $valor_kg = $resina['Valor_Kg'];
    }
    
    return ($valor_kg / 1000) * $quantidade_material;
}

// Função para calcular a depreciação/manutenção
function calcularDepreciacao($tempo_impressao, $Valor_do_Bem, $Tempo_de_Vida_Util) {
    list($horas, $minutos, $segundos) = explode(":", $tempo_impressao);
    $tempo_impressao_minutos = ($horas * 60) + $minutos + ($segundos / 60);
    return ($Valor_do_Bem / ($Tempo_de_Vida_Util * 60)) * $tempo_impressao_minutos;
}

// Cálculo do custo de produção e lucro
function calcularCustoProducao($peca) {
    $quantidade_peca = $peca['quantidade_peca']; // Quantidade de peças

    $custo_energia = calcularCustoEnergia($peca['consumo_impressora'], $peca['tempo_impressao'], $peca['kWh_energia'], 
                                          $peca['ICMS'], $peca['PIS_PASEP'], $peca['COFINS'], $peca['TOTAL_horas']) * $quantidade_peca;
    $custo_material = calcularCustoMaterial($peca['tipo_impressora'], $peca['material_peca'], $peca['quantidade_material']) * $quantidade_peca;
    $depreciacao = calcularDepreciacao($peca['tempo_impressao'], $peca['Valor_do_Bem'], $peca['Tempo_de_Vida_Util']) * $quantidade_peca;
    
    // Cálculo do custo de produção
    $custo_producao = $custo_energia + $custo_material + $depreciacao;
    
    // Cálculo do valor de venda com lucro
    $valor_venda = $custo_producao + ($custo_producao * ($peca['lucro_produto'] / 100));
    
    // Cálculo do lucro
    $lucro = $valor_venda - $custo_producao;
    
    return [
        'custo_energia' => $custo_energia,
        'custo_material' => $custo_material,
        'depreciacao' => $depreciacao,
        'custo_producao' => $custo_producao,
        'valor_venda' => $valor_venda,
        'lucro' => $lucro,
        'quantidade_peca' => $quantidade_peca // Retornando a quantidade de peças
    ];
}
?>

<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Detalhes do Produto</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .carousel-control-prev-icon,
        .carousel-control-next-icon {
            background-color: rgba(0, 0, 0, 0.5); /* Cor preta com 50% de opacidade */
            border-radius: 50%; /* Tornar as setas circulares */
        }

        .img-produto {
            cursor: pointer;
            position: relative;
        }

        .img-produto:hover::after {
            content: "Clique para ver em tamanho grande";
            display: block;
            position: absolute;
            bottom: 5px;
            left: 50%;
            transform: translateX(-50%);
            background-color: rgba(0, 0, 0, 0.7);
            color: white;
            padding: 5px;
            border-radius: 3px;
            font-size: 12px;
        }

        .highlight-lucro {
            text-align: center;
            font-size: 1.4em;
            font-weight: bold;
            background-color: #d4edda; /* Verde suave para Lucro */
            color: #155724; /* Cor mais convidativa */
        }

        .highlight-venda {
            text-align: center;
            font-size: 1.4em;
            font-weight: bold;
            background-color: #c3e6cb; /* Verde suave para Valor de Venda */
            color: #155724; /* Cor mais convidativa */
        }

        .highlight-custo-total {
            text-align: center;
            font-size: 1.4em;
            font-weight: bold;
            background-color: #e3f2fd; /* Azul claro suave para Custo Total */
            color: #0d47a1; /* Azul escuro para contrastar bem */
        }
    </style>
</head>
<body>
    <div class="container mt-4 pt-5">
        <h2><?= htmlspecialchars($produto['nome']) ?></h2>
        <div class="d-flex flex-wrap">
            <img src="<?= htmlspecialchars($produto['caminho_imagem']) ?>" alt="Imagem do Produto" class="img-fluid img-produto mb-3 me-2" style="max-width: 300px;">
            <?php foreach ($imagens_adicionais as $imagem): ?>
                <div class="m-2">
                    <img src="/uploads/<?= htmlspecialchars($imagem['caminho_imagem']) ?>" alt="Imagem adicional" class="img-thumbnail img-produto" style="width: 100px; height: 100px;">
                </div>
            <?php endforeach; ?>
        </div>
        
        <ul class="list-group">
            <!-- Exibir a categoria do produto -->
            <li class="list-group-item">
                <strong>Categoria:</strong> <?= htmlspecialchars($produto['categoria_nome'] ?? 'Nenhuma categoria definida') ?>
            </li>

            <!-- Exibir os atributos da peça -->
            <?php
            // Buscar atributos da peça (usando a tabela produto_atributos)
            $stmt_atributos = $pdo->prepare("
                SELECT ca.nome_atributo, pa.valor 
                FROM produto_atributos pa
                JOIN categoria_atributos ca ON pa.atributo_id = ca.id
                WHERE pa.produto_id = ?
            ");
            $stmt_atributos->execute([$produto['id']]); // Usar o ID do produto
            $atributos = $stmt_atributos->fetchAll(PDO::FETCH_ASSOC);

            if (count($atributos) > 0) {
                foreach ($atributos as $atributo): 
                ?>
                    <li class="list-group-item">
                        <strong><?= htmlspecialchars($atributo['nome_atributo']) ?>:</strong> <?= htmlspecialchars($atributo['valor']) ?>
                    </li>
                <?php endforeach;
            } else {
                echo '<li class="list-group-item">Nenhum atributo encontrado.</li>';
            }
            ?>
            <!-- Exibir as tags do produto -->
            <li class="list-group-item">
                <strong>Tags:</strong>
                <?php if (count($tags) > 0): ?>
                    <?php foreach ($tags as $tag): ?>
                        <span class="badge bg-primary me-2"><?= htmlspecialchars($tag['nome']) ?></span>
                    <?php endforeach; ?>
                <?php else: ?>
                    <span>Nenhuma tag associada.</span>
                <?php endif; ?>
            </li>
            <li class="list-group-item"><strong>Vídeo:</strong> <a href="<?= htmlspecialchars($produto['video']) ?>" target="_blank">Assistir</a></li>
            <li class="list-group-item"><strong>Download:</strong> <a href="<?= htmlspecialchars($produto['baixar']) ?>" target="_blank">Baixar</a></li>
            <li class="list-group-item"><strong>Observações:</strong> <?= nl2br(htmlspecialchars($produto['observacoes'])) ?></li>
            <li class="list-group-item"><strong>Lucro Estimado:</strong> <?= number_format($produto['lucro'], 0, ',', '.') ?>%</li>
        </ul>

        <!-- Modal -->
        <div class="modal fade" id="imagemModal" tabindex="-1" aria-labelledby="imagemModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="imagemModalLabel">Imagens do Produto</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div id="carouselImagens" class="carousel slide" data-bs-ride="carousel">
                            <div class="carousel-inner">
                                <div class="carousel-item active">
                                    <img src="<?= htmlspecialchars($produto['caminho_imagem']) ?>" class="d-block w-100" alt="Imagem do Produto">
                                </div>
                                <?php foreach ($imagens_adicionais as $index => $imagem): ?>
                                    <div class="carousel-item">
                                        <img src="/uploads/<?= htmlspecialchars($imagem['caminho_imagem']) ?>" class="d-block w-100" alt="Imagem adicional">
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <button class="carousel-control-prev" type="button" data-bs-target="#carouselImagens" data-bs-slide="prev">
                                <span class="carousel-control-prev-icon" aria-hidden="true"></span>
                                <span class="visually-hidden">Previous</span>
                            </button>
                            <button class="carousel-control-next" type="button" data-bs-target="#carouselImagens" data-bs-slide="next">
                                <span class="carousel-control-next-icon" aria-hidden="true"></span>
                                <span class="visually-hidden">Next</span>
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <h3 class="mt-4">Detalhes da Peça Associada</h3>
        <ul class="list-group">
            <?php foreach ($pecas as $peca): 
                $custos = calcularCustoProducao($peca);
            ?>
                <li class="list-group-item">
                    <img src="<?= htmlspecialchars($peca['imagem_peca']) ?>" alt="Imagem da Peça" class="img-fluid mb-2" style="max-width: 100px;">
                    <strong><?= htmlspecialchars($peca['nome_peca']) ?></strong> - 
                    <?= htmlspecialchars($peca['material_peca']) ?>
                    <br>
                    <small>Quantidade de Material: <?= number_format($peca['quantidade_material'], 2, ',', '.') ?> g</small>
                    <br>
                    <small>Tempo de Impressão: <?= htmlspecialchars($peca['tempo_impressao']) ?></small>
                    <br>
                    <small>Impressora: <?= htmlspecialchars($peca['marca_impressora']) ?> - <?= htmlspecialchars($peca['modelo_impressora']) ?></small>
                    <br>
                    <small>Tipo da Impressora: <?= htmlspecialchars($peca['tipo_impressora']) ?></small>
                    <br>
                    <small>Localização: <?= htmlspecialchars($peca['localizacao_impressora']) ?></small>
                    <br>
                    <small>Consumo de Energia: <?= number_format($peca['consumo_impressora'], 3, ',', '.') ?> kWh</small>
                </li>
            <?php endforeach; ?>
        </ul>

        <h3 class="mt-4">Componentes Associados</h3>
        <ul class="list-group">
            <?php foreach ($componentes as $componente): ?>
                <li class="list-group-item">
                    <img src="<?= htmlspecialchars($componente['caminho_imagem']) ?>" alt="Imagem da Peça" class="img-fluid mb-2" style="max-width: 100px;">
                    <strong><?= htmlspecialchars($componente['nome_material']) ?></strong> - <?= htmlspecialchars($componente['tipo_material']) ?>
                    <br>
                    <small>Descrição: <?= htmlspecialchars($componente['descricao']) ?></small>
                    <br>
                    <small>Unidade de Medida: <?= htmlspecialchars($componente['unidade_medida']) ?></small>
                    <br>
                    <small>Preço Unitário: R$ <?= number_format($componente['preco_unitario'], 2, ',', '.') ?></small>
                    <br>
                    <small>Fornecedor: <?= htmlspecialchars($componente['fornecedor']) ?></small>
                    <br>
                    <small>Observações: <?= htmlspecialchars($componente['observacoes']) ?></small>
                </li>
            <?php endforeach; ?>
        </ul>

        <h3 class="mt-4">Cálculo do Custo de Produção</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Peça</th>
                    <th>Quantidade</th>
                    <th>Custo de Energia (R$)</th>
                    <th>Custo de Material (R$)</th>
                    <th>Depreciação/Manutenção (R$)</th>
                    <th>Custo de Produção (R$)</th>
                    <th>Lucro (R$)</th>
                    <th>Valor de Venda (R$)</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($pecas as $peca): 
                    $custos = calcularCustoProducao($peca);
                ?>
                <tr>
                    <td><?= htmlspecialchars($peca['nome_peca']) ?></td>
                    <td><?= htmlspecialchars($custos['quantidade_peca']) ?></td>
                    <td>R$ <?= number_format($custos['custo_energia'], 2, ',', '.') ?></td>
                    <td>R$ <?= number_format($custos['custo_material'], 2, ',', '.') ?></td>
                    <td>R$ <?= number_format($custos['depreciacao'], 2, ',', '.') ?></td>
                    <td>R$ <?= number_format($custos['custo_producao'], 2, ',', '.') ?></td>
                    <td>R$ <?= number_format($custos['lucro'], 2, ',', '.') ?></td>
                    <td>R$ <?= number_format($custos['valor_venda'], 2, ',', '.') ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <?php if ($peca['tipo_impressora'] == 'Resina'): ?>
            <h3 class="mt-4">Cálculo do Custo de Lavagem e Cura</h3>
            <table class="table">
                <thead>
                    <tr>
                        <th>Peça</th>
                        <th>Quantidade</th>
                        <th>Custo de Energia (R$)</th>
                        <th>Custo de Material (R$)</th>
                        <th>Depreciação/Manutenção (R$)</th>
                        <th>Custo de Produção (R$)</th>
                        <th>Lucro (R$)</th>
                        <th>Valor de Venda (R$)</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($pecas as $peca): 
                        if ($peca['tipo_impressora'] == 'Resina') {
                            $quantidade_peca = $peca['quantidade_peca']; // Quantidade de peças
                    
                            $custo_energia_lavagem = calcularCustoEnergiaLavagem(
                                $peca['consumo_estacao'], $peca['tempo_lavagem'], $peca['tempo_cura'], 
                                $peca['kWh_energia'], $peca['ICMS'], $peca['PIS_PASEP'], $peca['COFINS'], $peca['TOTAL_horas']
                            ) * $quantidade_peca; // Multiplicando pela quantidade
                    
                            $custo_material_lavagem = calcularCustoMaterialLavagem(
                                $peca['quantidade_material'], $peca['valor_lavagem'], $peca['fator_consumo_lavagem']
                            ) * $quantidade_peca; // Multiplicando pela quantidade
                    
                            $depreciacao_lavagem = calcularDepreciacaoLavagem(
                                $peca['tempo_lavagem'], $peca['tempo_cura'], $peca['valor_estacao'], $peca['vida_util_estacao']
                            ) * $quantidade_peca; // Multiplicando pela quantidade
                    
                            $custo_producao_lavagem = $custo_energia_lavagem + $custo_material_lavagem + $depreciacao_lavagem;
                            $valor_venda_lavagem = $custo_producao_lavagem + ($custo_producao_lavagem * ($peca['lucro_produto'] / 100));
                            $lucro_lavagem = $valor_venda_lavagem - $custo_producao_lavagem;
                        }
                    ?>
                    <tr>
                        <td><?= htmlspecialchars($peca['nome_peca']) ?></td>
                        <td><?= htmlspecialchars($quantidade_peca) ?></td>
                        <td>R$ <?= number_format($custo_energia_lavagem, 2, ',', '.') ?></td>
                        <td>R$ <?= number_format($custo_material_lavagem, 2, ',', '.') ?></td>
                        <td>R$ <?= number_format($depreciacao_lavagem, 2, ',', '.') ?></td>
                        <td>R$ <?= number_format($custo_producao_lavagem, 2, ',', '.') ?></td>
                        <td>R$ <?= number_format($lucro_lavagem, 2, ',', '.') ?></td>
                        <td>R$ <?= number_format($valor_venda_lavagem, 2, ',', '.') ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        <?php endif; ?>

        <h3 class="mt-4">Cálculo do Custo de Componentes</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Componente</th>
                    <th>Unidade</th>
                    <th>Quantidade</th>
                    <th>Custo Unitário (R$)</th>
                    <th>Custo Total (R$)</th>
                    <th>Lucro (R$)</th>
                    <th>Valor de Venda (R$)</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($componentes as $componente): 
                    $stmt_quantidade = $pdo->prepare("SELECT quantidade FROM produtos_componentes WHERE produto_id = ? AND componente_id = ?");
                    $stmt_quantidade->execute([$id, $componente['id']]);
                    $quantidade = $stmt_quantidade->fetchColumn();
                    
                    $custo_total = $componente['preco_unitario'] * $quantidade;
                    $lucro = $custo_total * ($produto['lucro'] / 100);
                    $valor_venda = $custo_total + $lucro;
                ?>
                <tr>
                    <td><?= htmlspecialchars($componente['nome_material']) ?></td>
                    <td><?= htmlspecialchars($componente['unidade_medida']) ?></td>
                    <td><?= $quantidade ?></td>
                    <td>R$ <?= number_format($componente['preco_unitario'], 2, ',', '.') ?></td>
                    <td>R$ <?= number_format($custo_total, 2, ',', '.') ?></td>
                    <td>R$ <?= number_format($lucro, 2, ',', '.') ?></td>
                    <td>R$ <?= number_format($valor_venda, 2, ',', '.') ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>

        <h3 class="mt-4">Totalização dos Valores</h3>
        <table class="table">
            <thead>
                <tr>
                    <th>Total Custo de Produção (R$)</th>
                    <th>Total Custo de Componentes (R$)</th>
                    <th class="highlight-custo-total">Custo Total (R$)</th> <!-- Nova coluna -->
                    <th class="highlight-lucro">Total Lucro (R$)</th>
                    <th class="highlight-venda">Valor de Venda Sugerido (R$)</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <?php 
                        $total_custo_producao = 0;
                        $total_custo_total = 0;
                        $total_lucro = 0;
                        $total_valor_venda = 0;
                        $total_custo_lavagem = 0;
                        $total_lucro_lavagem = 0; // Novo: Total de lucro da lavagem
                        $total_valor_venda_lavagem = 0; // Novo: Total de valor de venda da lavagem
                        
                        foreach ($pecas as $peca) {
                            $custos = calcularCustoProducao($peca);
                            $total_custo_producao += $custos['custo_producao'];
                            $total_lucro += $custos['lucro'];
                            $total_valor_venda += $custos['valor_venda'];
                        }
                        
                        foreach ($pecas as $peca) {
                            if ($peca['tipo_impressora'] == 'Resina') {
                                $quantidade_peca = $peca['quantidade_peca']; // Quantidade de peças
                        
                                $custo_energia_lavagem = calcularCustoEnergiaLavagem(
                                    $peca['consumo_estacao'], $peca['tempo_lavagem'], $peca['tempo_cura'], 
                                    $peca['kWh_energia'], $peca['ICMS'], $peca['PIS_PASEP'], $peca['COFINS'], $peca['TOTAL_horas']
                                ) * $quantidade_peca;
                        
                                $custo_material_lavagem = calcularCustoMaterialLavagem(
                                    $peca['quantidade_material'], $peca['valor_lavagem'], $peca['fator_consumo_lavagem']
                                ) * $quantidade_peca;
                        
                                $depreciacao_lavagem = calcularDepreciacaoLavagem(
                                    $peca['tempo_lavagem'], $peca['tempo_cura'], $peca['valor_estacao'], $peca['vida_util_estacao']
                                ) * $quantidade_peca;
                        
                                $custo_producao_lavagem = $custo_energia_lavagem + $custo_material_lavagem + $depreciacao_lavagem;
                                $valor_venda_lavagem = $custo_producao_lavagem + ($custo_producao_lavagem * ($peca['lucro_produto'] / 100));
                                $lucro_lavagem = $valor_venda_lavagem - $custo_producao_lavagem;
                        
                                $total_custo_lavagem += $custo_producao_lavagem;
                                $total_lucro_lavagem += $lucro_lavagem; // Somando o lucro da lavagem
                                $total_valor_venda_lavagem += $valor_venda_lavagem; // Somando o valor de venda da lavagem
                            }
                        }
                        
                        foreach ($componentes as $componente) {
                            $stmt_quantidade = $pdo->prepare("SELECT quantidade FROM produtos_componentes WHERE produto_id = ? AND componente_id = ?");
                            $stmt_quantidade->execute([$id, $componente['id']]);
                            $quantidade = $stmt_quantidade->fetchColumn();
                            
                            $custo_total = $componente['preco_unitario'] * $quantidade;
                            $lucro = $custo_total * ($produto['lucro'] / 100);
                            $valor_venda = $custo_total + $lucro;
                        
                            $total_custo_total += $custo_total;
                            $total_lucro += $lucro;
                            $total_valor_venda += $valor_venda;
                        }
                        
                        // Calculando o Custo Total (Custo de Produção + Custo de Lavagem + Custo de Componentes)
                        $custo_total_geral = $total_custo_producao + $total_custo_lavagem + $total_custo_total;
                        
                        // Somando o lucro e o valor de venda da lavagem aos totais gerais
                        $total_lucro += $total_lucro_lavagem;
                        $total_valor_venda += $total_valor_venda_lavagem;
                        
                        // Somando o custo de produção da lavagem ao Total Custo de Produção
                        $total_custo_producao += $total_custo_lavagem;
                    ?>
                    <td style="font-size: 1.2em;">R$ <?= number_format($total_custo_producao, 2, ',', '.') ?></td>
                    <td style="font-size: 1.2em;">R$ <?= number_format($total_custo_total, 2, ',', '.') ?></td>
                    <td class="highlight-custo-total" style="font-size: 1.4em; font-weight: bold; background-color: #e3f2fd; color: #0d47a1;" >R$ <?= number_format($custo_total_geral, 2, ',', '.') ?></td> <!-- Exibindo o Custo Total -->
                    <td class="highlight-lucro" style="font-size: 1.4em; font-weight: bold; background-color: #d4edda; color: #155724;">R$ <?= number_format($total_lucro, 2, ',', '.') ?></td>
                    <td class="highlight-venda" style="font-size: 1.4em; font-weight: bold; background-color: #c3e6cb; color: #155724;">R$ <?= number_format($total_valor_venda, 2, ',', '.') ?></td>
                </tr>
            </tbody>
        </table>

        <style>
            .highlight-lucro {
                text-align: center;
                font-size: 1.4em;
                font-weight: bold;
                background-color: #d4edda; /* Verde suave para Lucro */
                color: #155724; /* Cor mais convidativa */
            }

            .highlight-venda {
                text-align: center;
                font-size: 1.4em;
                font-weight: bold;
                background-color: #c3e6cb; /* Verde suave para Valor de Venda */
                color: #155724; /* Cor mais convidativa */
            }

            .highlight-custo-total {
                text-align: center;
                font-size: 1.4em;
                font-weight: bold;
                background-color: #e3f2fd; /* Azul claro suave para Custo Total */
                color: #0d47a1; /* Azul escuro para contrastar bem */
            }
        </style>

    </div>
    <div class="mt-4 text-center">
        <a href="../views/index.php" class="btn btn-secondary mt-3">Voltar</a>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const imagens = document.querySelectorAll('.img-produto');
            const modal = new bootstrap.Modal(document.getElementById('imagemModal'));
            const carousel = document.getElementById('carouselImagens');
            
            imagens.forEach((imagem, index) => {
                imagem.addEventListener('click', function() {
                    const carouselInstance = bootstrap.Carousel.getInstance(carousel);
                    carouselInstance.to(index); // Ajuste o índice conforme necessário
                    modal.show();
                });
            });
        });
    </script>
</body>
</html>