messages = readtable('./messages.csv', 'Format', '%C%d%d%d%f%f%f%f%f%f')

U = messages(messages.category == 'u',:);
S = messages(messages.category == 's',:);
fig = figure;

subplot(1,2,1)
errorbar(U{:,4},U{:,7},U{:,7}-U{:,5},U{:,7}-U{:,10}, 'LineStyle', 'none', 'Marker', 'x')

%set(gca,'yscale','log')
ylim([0,25])
yticks([0,1,5,10,15,20,25])

xlabel("Unsecured")
xlim([0,21])
xticks([1,5,10,15,20])

subplot(1,2,2)
errorbar(S{:,4},S{:,7},S{:,7}-S{:,5},S{:,7}-S{:,10}, 'LineStyle', 'none', 'Marker', 'x')

%set(gca,'yscale','log')
ylim([0,25])

xlabel("Secured")
xlim([0,21])
xticks([1,5,10,15,20])

han = axes(fig,'visible', 'off');

han.XLabel.Visible='on';
xlabel(han, "# Messages")

han.YLabel.Visible='on';
ylabel(han, "Time [s]")

% han.Title.Visible='on';
% title(han,"Min, Median, Max Runtime by # Participants")