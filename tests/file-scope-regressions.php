<?php
// Standalone request/ownership regressions. Live file I/O is tested separately.
require __DIR__.'/session-regressions.php';
class Records {
    public static function getDataTable($projectId) { return 'redcap_data'; }
}
$scope = ['project_id'=>1, 'survey_id'=>2, 'form_name'=>'survey', 'event_id'=>3, 'record'=>'12', 'instance'=>2];
$upload = ['__passthru'=>'DataEntry/file_upload.php', 'pid'=>'1', 's'=>'private', 'id'=>'12', 'event_id'=>'3', 'instance'=>'2'];
function fileAllowed($get, $post=[], $request=[], $results=[]) {
    global $module, $fixture, $scope;
    $_GET=$get; $_POST=$post; $_REQUEST=$request;
    $_SERVER['REQUEST_METHOD']='POST';
    $fixture->queries=[]; $fixture->results=$results;
    return callPrivate($module, 'surveyFileRequestAllowed', $scope);
}
check(fileAllowed($upload, ['field_name'=>'file-upload'], [], [[[1]]]), 'Matching upload reaches field lookup');
check($fixture->queries[0][1]===[1,'survey','file','file'], 'Upload field is bound to the instrument');
foreach (['id'=>'13', 'event_id'=>'4', 'instance'=>'3', 'pid'=>'2', 'page'=>'other', '__passthru'=>[]] as $key=>$value) {
    check(!fileAllowed(array_replace($upload, [$key=>$value]), ['field_name'=>'file-upload']), 'Reject upload parameter '.$key);
    check(!$fixture->queries, 'Mismatched routing fails before file queries');
}
foreach (['pid'=>'2', 'event_id'=>'4', 'instance'=>'3'] as $key=>$value) {
    check(!fileAllowed($upload, ['field_name'=>'file-upload', $key=>$value]), 'Reject conflicting POST '.$key);
    check(!fileAllowed($upload, ['field_name'=>'file-upload'], [$key=>$value]), 'Reject conflicting REQUEST '.$key);
}
foreach ([[], null, 'file'] as $field) {
    check(!fileAllowed($upload, ['field_name'=>$field]), 'Reject malformed upload field');
}
check(!fileAllowed($upload, ['field_name'=>'file-upload'], [], [[]]), 'Reject field outside this survey');
$scope['record']=null;
check(!fileAllowed($upload, ['field_name'=>'file-upload']), 'Public grant cannot choose an arbitrary upload record');
$scope['record']='12';
$download=array_replace($upload, ['__passthru'=>'DataEntry/file_download.php','id'=>'42','record'=>'12','field_name'=>'file','page'=>'survey']);
check(fileAllowed($download, [], [], [[[1]]]), 'Matching owned document is allowed');
check($fixture->queries[0][1]===['survey',1,'42','file','file','12',3,2,'12',3,2], 'Current and pending documents use the exact response location');
check(!fileAllowed($download, [], [], [[]]), 'Valid document ID without ownership is rejected');
foreach (['record'=>'13','field_name'=>[], 'id'=>[], 'instance'=>'1'] as $key=>$value) {
    check(!fileAllowed(array_replace($download,[$key=>$value])), 'Reject malformed or mismatched download '.$key);
}
$image=['__passthru'=>'DataEntry/image_view.php','id'=>'42'];
check(fileAllowed($image, [], [], [[[1]]]), 'Configured survey content is allowed');
check($fixture->queries[0][1]===[1,2,'42'], 'Static content is restricted to this project and survey');
check(fileAllowed($image, [], [], [[],[[1]]]), 'Response image can resolve scope without client record or field');
check($fixture->queries[1][1]===['survey',1,'42',null,null,'12',3,2,'12',3,2], 'Image ownership comes from the authorized response');
check(!fileAllowed($image, [], [], [[],[]]), 'Foreign image fails both content and response ownership checks');
check(!fileAllowed(array_replace($download,['type'=>'attachment']), [], [], [[]]), 'Attachment flag cannot turn response data into survey content');
check(!fileAllowed(array_replace($download,['__passthru'=>'DataEntry%2Ffile_delete.php']), [], [], [[]]), 'Encoded delete route still checks ownership');
echo "Passed survey file scope regressions.\n";
