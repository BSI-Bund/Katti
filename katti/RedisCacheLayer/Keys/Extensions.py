extension_kwargs_key = lambda redis_channel_id: f'extension_{redis_channel_id}_kwargs'

report_pipeline_head = lambda report_id: f'report_pipeline_head_{report_id}'


report_raw_data_key = lambda report_id: f'report_raw_data{report_id}'

report_final_report_key = lambda run_id, report_id: f'report_final_report{run_id}{report_id}'

report_ooi_input_cache = lambda report_id: f'report_ooi_input{report_id}'

report_pipeline_run_cache = lambda report_id: f'report_pipeline_cache{report_id}'

report_app_pipeline_cache = lambda app: f'app_pipe_cache{app.id}{app.version}'

shiv_app_start_kwargs = lambda start_id: f'shiv_app_kwargs{start_id}'