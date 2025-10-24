## Экспортер метрик для https://stormwall.pro/


Сборка образа контейнера
```
docker build -t stormwall-exporter:latest .
```

Добавляется в prometheus как и все остальные экспортеры, думаю разберётесь. 
P.S. Не забудьте указать ваш токен и номера услуг в compose файле.

Пример дашборда в файле grafana-dashboard.json
