<?php
require dirname(__DIR__) . '/src/SecretServerClient.php';
$c=new SecretServer\SecretServerClient(getenv('SS_LIVE_KEY'),getenv('SS_LIVE_URL'));
$c->createSecret('php-live','first',['container_id'=>getenv('SS_LIVE_CONTAINER')]);
if($c->secret('prod/php-live')!=='first') throw new RuntimeException('path mismatch');
$c->updateSecret('php-live','second');
if($c->secret('php-live')!=='second') throw new RuntimeException('update mismatch');
$record=$c->getSecret('php-live');
$c->assignVariable('PHP_LIVE','secret',$record['id'],'value');
if($c->render('x=%%PHP_LIVE%%')!=='x=second') throw new RuntimeException('render mismatch');
$document=$c->resolveDocument(['password'=>'%%PHP_LIVE%%','count'=>2]);
if($document->password!=='second' || $document->count!==2) throw new RuntimeException('document mismatch');
if($c->getVariable('PHP_LIVE')['secret_id']!==$record['id']) throw new RuntimeException('binding mismatch');
$c->listVariables();
foreach (['{}','{"0":"%%PHP_LIVE%%"}','{"empty":{},"list":[],"nested":[{"0":"%%PHP_LIVE%%"}]}'] as $json) {
    $input=json_decode($json, false, 512, JSON_THROW_ON_ERROR);
    $resolved=$c->resolveDocument($input);
    $expected=str_replace('%%PHP_LIVE%%','second',$json);
    if(json_encode($resolved)!==json_encode(json_decode($expected))) throw new RuntimeException('object/list shape changed');
}
$c->deleteVariable('PHP_LIVE');
$c->deleteSecret('php-live');
echo "PHP live contract PASS\n";
